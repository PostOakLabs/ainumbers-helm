// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-cfportal-1: RED-before-GREEN row test.
//
// Proves, through the SAME verifier the demo already ships (ui/lib/
// verify-bundle.mjs, the one verify.html embeds; `helmd verify` is the CLI
// face of the same check):
//   - cfportal.golden.jsonl imports to a generic log that seals into a bundle
//     that verifies VALID (GOLDEN);
//   - cfportal.tampered.jsonl — the SAME log with ONE byte flipped inside a
//     request_digest — cannot become a bundle: the shared runner cross-checks
//     a body-bearing line's digest against sha256(body) and refuses; and the
//     tamper the flip represents at the sealed record (the flipped digest
//     byte applied at the bundle record) is INVALID to the same verifier
//     (TAMPERED-LOG / TAMPERED-BUNDLE);
//   - a line carrying a raw request body is hashed and the body NEVER reaches
//     the bundle text (BODY-DROP);
//   - a line with neither body nor digest is refused with reason `no_digest`
//     (RUNNER-REFUSAL);
//   - the Cloudflare field names land where the map says: tool.invoke:<tool>,
//     prompt.get:<prompt>, resource.read:<uri>, ServerURL hostname, UserID
//     actor, portal scope, dlp_label classification (FIELD-MAPPING).
// The CI run order is RED (before the importer exists) then GREEN.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { importCfPortalLog as importLog } from "./cfportal.mjs";
import { verifyBundle } from "../../ui/lib/verify-bundle.mjs";
import { hashBody } from "./_map.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN = readFileSync(join(HERE, "..", "..", "fixtures", "gwlog", "cfportal.golden.jsonl"), "utf8");
const TAMPERED = readFileSync(join(HERE, "..", "..", "fixtures", "gwlog", "cfportal.tampered.jsonl"), "utf8");
const GOLDEN_ID = "bundle-gwlog-cfportal-1";
const TAMPER_ID = "bundle-gwlog-cfportal-tampered-1";

test("fixture pair sanity: tampered is golden with exactly one byte flipped in a digest", () => {
  let diff = 0, flippedLines = 0;
  const g = GOLDEN.split("\n"), t = TAMPERED.split("\n");
  assert.equal(g.length, t.length, "tampered fixture must have the same number of lines as golden");
  for (let i = 0; i < g.length; i++) {
    assert.equal(g[i].length, t[i].length, `line ${i + 1} length must be unchanged`);
    let changed = false;
    for (let j = 0; j < g[i].length; j++) if (g[i][j] !== t[i][j]) diff++;
    if (g[i] !== t[i]) { changed = true; flippedLines++; assert.ok(/_digest/.test(g[i]) && /_digest/.test(t[i]), `changed line ${i + 1} carries a digest`); }
  }
  assert.equal(flippedLines, 1, "the flip must land on exactly one line");
  assert.equal(diff, 1, `exactly one flipped byte expected, found ${diff}`);
});

test("GOLDEN-BUNDLE: importer output verifies VALID through the shipped offline verifier", async () => {
  const { bundle, publicKeys } = importLog({ jsonlText: GOLDEN, bundleId: GOLDEN_ID });
  assert.ok(bundle, "golden import must produce a bundle");
  const result = await verifyBundle(bundle, publicKeys);
  assert.equal(result.valid, true, `expected VALID, got reasons: ${result.reasons?.join("; ")}`);
});

test("TAMPERED-LOG: the flipped digest byte cannot become a bundle — importer refuses", () => {
  assert.throws(
    () => importLog({ jsonlText: TAMPERED, bundleId: TAMPER_ID }),
    (err) => {
      const reason = err.message;
      return /digest_mismatch/.test(reason) || /no_digest/.test(reason);
    },
    "importer must refuse a log line whose digest no longer matches its body"
  );
});

test("TAMPERED-BUNDLE: the same flip at the bundle record is INVALID to the SAME verifier", async () => {
  const { bundle, publicKeys } = importLog({ jsonlText: GOLDEN, bundleId: GOLDEN_ID });
  const flipped = structuredClone(bundle);
  const hex = flipped.objects[0].digest.replace(/^sha256:/, "");
  flipped.objects[0].digest = `sha256:${(hex[0] === "f" ? "0" : "f") + hex.slice(1)}`;
  const verdict = await verifyBundle(flipped, publicKeys);
  assert.equal(verdict.valid, false, "a flipped digest byte in the sealed record must NOT verify");
});

test("BODY-DROP: a raw request body is hashed and never reaches the bundle", () => {
  const body = "CFPORTAL-SECRET-PAYLOAD-body-must-not-reach-the-bundle";
  const jsonlText = JSON.stringify({
    Datetime: "2026-09-09T12:00:00.000Z",
    Method: "tools/call",
    ToolCallName: "vault-balance",
    SessionID: "sess-cf-7a01",
    PortalID: "portal-3101",
    ServerURL: "https://vault-mcp.example.com/sse",
    ServerID: "srv-8873",
    UserID: "u-cf-101",
    request_body: body,
    response_digest: `sha256:${"2".repeat(64)}`,
  }) + "\n";
  const { jsonl } = importLog({ jsonlText, bundleId: GOLDEN_ID });
  assert.ok(!jsonl.includes(body), "the raw body must be dropped before anything is written");
  assert.ok(jsonl.includes(`"request_digest":"sha256:`), "digests still present");
  const ts = JSON.parse(jsonl.trim());
  assert.equal(ts.request_digest, hashBody(body));
});

test("RUNNER-REFUSAL: a line with neither body nor digest is refused with reason no_digest", () => {
  const jsonlText = JSON.stringify({
    Datetime: "2026-09-09T12:00:00.000Z",
    Method: "tools/call",
    ToolCallName: "vault-balance",
    ServerURL: "https://vault-mcp.example.com/sse",
  }) + "\n";
  assert.throws(
    () => importLog({ jsonlText, bundleId: GOLDEN_ID }),
    (err) => /no_digest/.test(err.message),
    "runner must refuse a line that carries neither a body nor a digest"
  );
});

test("FIELD-MAPPING: Cloudflare mcp_portal_logs fields land in the generic shape", () => {
  const { jsonl, rows } = importLog({ jsonlText: GOLDEN, bundleId: GOLDEN_ID });
  const lines = jsonl.trim().split("\n").map((l) => JSON.parse(l));
  // agents' actor: the authenticated user
  assert.ok(rows.every((r) => r.actor_id.startsWith("u-cf-")), `actor_id from UserID: ${rows.map((r) => r.actor_id).join(",")}`);
  // action: MCP method + tool name
  assert.equal(lines[0].action, "tool.invoke:vault-balance");
  assert.equal(lines[1].action, "prompt.get:incident-summary");
  assert.equal(lines[2].action.startsWith("resource.read:file://"), true, `resources/read with ResourceReadURI: ${lines[2].action}`);
  // target_host: ServerURL hostname
  assert.equal(lines[0].target_host, "vault-mcp.example.com");
  assert.equal(lines[4].target_host, "billing-mcp.example.net");
  // scope: the portal is the governance scope
  assert.ok(lines[0].scope.includes("portal:portal-3101") && lines[0].scope.includes("server:srv-8873"));
  // classification: dlp_label when present, fault on a failed call, else internal
  assert.equal(rows[4].classification.startsWith("dlp:"), true, `dlp_label: ${rows[4].classification}`);
  assert.equal(rows[3].classification, "fault");
  assert.ok([0, 1, 2].every((i) => lines[i].classification === "internal"));
  // actor_version is not a Cloudflare field — exactly "unknown"
  assert.ok(rows.every((r) => r.actor_version === "unknown"));
});

