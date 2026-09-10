// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-agent365-1: RED-before-GREEN row test.
//
// Proves, through the SAME verifier the demo already ships (ui/lib/
// verify-bundle.mjs, the one verify.html embeds; `helmd verify` is the CLI
// face of the same check):
//   - agent365.golden.jsonl imports to a generic log that seals into a
//     bundle that verifies VALID (GOLDEN);
//   - agent365.tampered.jsonl — the SAME log with ONE byte flipped inside a
//     request_digest — cannot become a bundle: the importer cross-checks a
//     body-bearing line's digest against sha256(body) and refuses; and the
//     tamper the log flip represents in the sealed record (the flipped
//     digest byte applied at the bundle record) is INVALID to the same
//     verifier;
//   - a raw `AuditData.Messages` body is hashed and NEVER reaches the
//     bundle text (BODY-DROP);
//   - a Purview record with neither `AuditData.Messages` nor an enrichment
//     digest is refused with reason `no_digest` (RUNNER-REFUSAL).
// The run order in CI is RED (before the importer exists) then GREEN.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { importAgent365Log as importLog } from "./agent365.mjs";
import { verifyBundle } from "../../ui/lib/verify-bundle.mjs";
import { hashBody } from "./_map.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN = readFileSync(join(HERE, "..", "..", "fixtures", "gwlog", "agent365.golden.jsonl"), "utf8");
const TAMPERED = readFileSync(join(HERE, "..", "..", "fixtures", "gwlog", "agent365.tampered.jsonl"), "utf8");
const GOLDEN_ID = "bundle-gwlog-agent365-1";
const TAMPER_ID = "bundle-gwlog-agent365-tampered-1";

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
  const { bundle, publicKeys } = importLog({
    jsonlText: GOLDEN, bundleId: GOLDEN_ID,
  });
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
  const tampered = structuredClone(bundle);
  tampered.objects[0].envelope.signatures[0].sig = Buffer.from("not a real signature").toString("base64");
  // does the same verifier catch it? (mirrors GWLOG-DEMO-1's tamper shape)
  const sigVerdict = await verifyBundle(tampered, publicKeys);
  assert.equal(sigVerdict.valid, false, "a flipped envelope signature must NOT verify");
  // The bundle-level image of the log's digest flip — the flipped byte lands
  // on the sealed record's content digest — is caught by the SAME verifier:
  const flipped = structuredClone(bundle);
  const hex = flipped.objects[0].digest.replace(/^sha256:/, "");
  flipped.objects[0].digest = `sha256:${hex.slice(1) + (hex[0] === "f" ? "0" : "f")}`;
  const verdict = await verifyBundle(flipped, publicKeys);
  assert.equal(verdict.valid, false, "a flipped digest byte in the sealed record must NOT verify");
});

test("BODY-DROP: a raw AuditData.Messages body is hashed and never reaches the bundle", () => {
  const promptId = "1715555555000";
  const respId = "1715555555777";
  const messages = [{ ID: promptId, isPrompt: true }, { ID: respId, isPrompt: false }];
  const jsonlText = JSON.stringify({
    Id: "8e2b4d6f-9999-48f4-b568-3a4c8ae75d21",
    CreationTime: "2026-09-09T12:00:30.000Z",
    Operation: "CopilotInteraction",
    Workload: "Copilot",
    AuditData: {
      AgentId: "CopilotStudio.CustomEngine.11fd28b5-4452-4615-be3d-7046a6f31131",
      AppHost: "BizChat",
      Messages: messages,
    },
  }) + "\n";
  const { jsonl } = importLog({ jsonlText, bundleId: GOLDEN_ID });
  assert.ok(!jsonl.includes(promptId), "the raw prompt side must be dropped before anything is written");
  assert.ok(!jsonl.includes(respId), "the raw response side must be dropped before anything is written");
  assert.ok(jsonl.includes(`request_digest":"sha256:`), "digests still present");
  // cross-check the request digest is the recorded body hash:
  const row = JSON.parse(jsonl.trim());
  assert.equal(row.request_digest, hashBody(messages));
  assert.equal(row.actor_id, "CopilotStudio.CustomEngine.11fd28b5-4452-4615-be3d-7046a6f31131");
});

test("RUNNER-REFUSAL: a record with neither AuditData.Messages nor a digest is refused with reason no_digest", () => {
  const jsonlText = JSON.stringify({
    Id: "8e2b4d6f-8888-48f4-b568-3a4c8ae75d21",
    CreationTime: "2026-09-09T12:00:40.000Z",
    Operation: "CopilotInteraction",
    Workload: "Copilot",
    AuditData: {
      AgentId: "2a7c9d61-3344-4e0f-bb2d-77a1c93f4b12",
      AppHost: "Office",
    },
  }) + "\n";
  assert.throws(
    () => importLog({ jsonlText, bundleId: GOLDEN_ID }),
    (err) => /no_digest/.test(err.message),
    "runner must refuse a line that carries neither a body nor a digest"
  );
});
