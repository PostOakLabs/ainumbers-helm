// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-openclaw-1: RED-before-GREEN row test.
//
// Proves, through the SAME verifier the demo already ships (ui/lib/
// verify-bundle.mjs, the one verify.html embeds; `helmd verify` is the CLI
// face of the same check):
//   - openclaw.golden.jsonl imports to a generic log that seals into a bundle
//     that verifies VALID (GOLDEN);
//   - openclaw.tampered.jsonl — the SAME log with ONE byte flipped inside a
//     request_digest — cannot become a bundle: the importer cross-checks a
//     sidecar-body line's digest against sha256(body) and refuses; and the
//     same tamper applied at the bundle record is INVALID to the same
//     verifier;
//   - a line carrying a raw sidecar body is hashed and the body NEVER reaches
//     the bundle text (BODY-DROP);
//   - a line with neither body nor digest is refused with reason `no_digest`
//     (RUNNER-REFUSAL).
// The run order in CI is RED (before the importer exists) then GREEN.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { importOpenClawLog as importLog } from "./openclaw.mjs";
import { verifyBundle } from "../../ui/lib/verify-bundle.mjs";
import { hashBody } from "./_map.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN = readFileSync(join(HERE, "..", "..", "fixtures", "gwlog", "openclaw.golden.jsonl"), "utf8");
const TAMPERED = readFileSync(join(HERE, "..", "..", "fixtures", "gwlog", "openclaw.tampered.jsonl"), "utf8");
const GOLDEN_ID = "bundle-gwlog-openclaw-1";
const TAMPER_ID = "bundle-gwlog-openclaw-tampered-1";

test("fixture pair sanity: tampered is golden with exactly one byte flipped in a digest", () => {
  let diff = 0, flippedLines = 0;
  const g = GOLDEN.split("\n"), t = TAMPERED.split("\n");
  assert.equal(g.length, t.length, "tampered fixture must have the same number of lines as golden");
  for (let i = 0; i < g.length; i++) {
    assert.equal(g[i].length, t[i].length, `line ${i + 1} length must be unchanged`);
    if (g[i] !== t[i]) {
      flippedLines++;
      assert.ok(/_digest/.test(g[i]) && /_digest/.test(t[i]), `changed line ${i + 1} carries a digest`);
      for (let j = 0; j < g[i].length; j++) if (g[i][j] !== t[i][j]) diff++;
    }
  }
  assert.equal(flippedLines, 1, "the flip must land on exactly one line");
  assert.equal(diff, 1, `exactly one flipped byte expected, found ${diff}`);
});

test("GOLDEN-BUNDLE: importer output verifies VALID through the shipped offline verifier", async () => {
  const { bundle, publicKeys, rows } = importLog({
    jsonlText: GOLDEN, bundleId: GOLDEN_ID,
  });
  assert.ok(bundle, "golden import must produce a bundle");
  assert.equal(rows.length, 5, "five golden lines mapped");
  // documented field names survive into the generic shape where the map says:
  assert.equal(rows[0].actor_id, "ops-agent", "actor_id = documented agent_id");
  assert.equal(rows[0].run_id, "ses:sess-3f2a", "run_id from documented session_id");
  assert.equal(rows[0].action, "tool.exec", "action = tool name from the bound record");
  assert.equal(rows[0].scope[0], "tool-profile:exec-allowlisted", "scope from tool profile sidecar");
  assert.equal(rows[1].target_host, "docs.example.com", "target host from tool_target URL");
  assert.equal(rows[2].action, "model.fetch", "[model-fetch] hook records the model call");
  assert.equal(rows[2].target_host, "api.example.com", "model-transport url host");
  assert.equal(rows[3].action, "log.warn", "non-tool lines record their documented level");
  assert.equal(rows[4].actor_version, "unknown", "no actor version documented in the source");
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
  const tampered = structuredClone(bundle);
  tampered.objects[0].envelope.signatures[0].sig = Buffer.from("not a real signature").toString("base64");
  const sigVerdict = await verifyBundle(tampered, publicKeys);
  assert.equal(sigVerdict.valid, false, "a flipped envelope signature must NOT verify");
  const flipped = structuredClone(bundle);
  const hex = flipped.objects[0].digest.replace(/^sha256:/, "");
  flipped.objects[0].digest = `sha256:${hex.slice(1) + (hex[0] === "f" ? "0" : "f")}`;
  const verdict = await verifyBundle(flipped, publicKeys);
  assert.equal(verdict.valid, false, "a flipped digest byte in the sealed record must NOT verify");
});

test("BODY-DROP: a raw sidecar body is hashed and never reaches the bundle", () => {
  const body = "OPENCLAW-SIDECAR-SECRET-PAYLOAD-body-must-not-reach-the-bundle";
  const jsonlText = JSON.stringify({
    "0": { tool: "web_fetch", tool_target: "https://docs.example.com/spec" },
    "1": "[tools] web_fetch docs/spec",
    time: "2026-09-09T12:00:00.000Z",
    hostname: "gw-host-1",
    agent_id: "ops-agent",
    session_id: "sess-drop-1",
    "request.body": body,
    "response_digest": `sha256:${"2".repeat(64)}`,
  }) + "\n";
  const { jsonl } = importLog({ jsonlText, bundleId: GOLDEN_ID });
  assert.ok(!jsonl.includes(body), "the raw body must be dropped before anything is written");
  assert.ok(jsonl.includes(`request_digest":"sha256:`), "digests still present");
  const row = JSON.parse(jsonl.trim());
  assert.equal(row.request_digest, hashBody(body));
});

test("RUNNER-REFUSAL: a line with neither body nor digest is refused with reason no_digest", () => {
  const jsonlText = JSON.stringify({
    "1": "[gateway] ws result ok=false method=cron.list",
    time: "2026-09-09T12:00:00.000Z",
    hostname: "gw-host-1",
    session_id: "sess-nodigest-1",
  }) + "\n";
  assert.throws(
    () => importLog({ jsonlText, bundleId: GOLDEN_ID }),
    (err) => /no_digest/.test(err.message),
    "runner must refuse a line that carries neither a body nor a digest"
  );
});
