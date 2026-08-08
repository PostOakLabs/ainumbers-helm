// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// GWLOG-DEMO-1: RED-before-GREEN on the tamper case — the demo's punchline is
// that the EXISTING offline verifier (ui/lib/verify-bundle.mjs, the same code
// verify.html embeds) accepts the real fixture and rejects a byte-tampered
// sibling. Uses the shipped fixtures/agent-gateway-action-log.example.jsonl,
// not a hand-rolled input, so this test also proves the fixture round-trips.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildGwlogBundle, parseActionLogLine, readActionLog } from "./gwlog-to-bundle.mjs";
import { verifyBundle } from "../ui/lib/verify-bundle.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = readFileSync(join(HERE, "..", "fixtures", "agent-gateway-action-log.example.jsonl"), "utf8");

test("parseActionLogLine: rejects a line missing a required field", () => {
  assert.throws(() => parseActionLogLine('{"ts":"2026-08-08T00:00:00Z"}', 1), /missing required field/);
});

test("parseActionLogLine: rejects a non-sha256 digest", () => {
  const bad = JSON.stringify({
    ts: "2026-08-08T00:00:00Z", run_id: "r", actor_id: "a", actor_version: "1",
    action: "x", target_host: "h", scope: [], request_digest: "not-a-digest",
    response_digest: `sha256:${"1".repeat(64)}`, classification: "internal",
  });
  assert.throws(() => parseActionLogLine(bad, 1), /request_digest.*sha256/);
});

test("readActionLog: parses the shipped example fixture into 3 rows", () => {
  const rows = readActionLog(FIXTURE);
  assert.equal(rows.length, 3);
  assert.equal(rows[0].actor_id, "agent:research-bot-7");
});

test("buildGwlogBundle: converts the fixture into a bundle sealing one connector_attestation per action", () => {
  const { bundle } = buildGwlogBundle(FIXTURE);
  assert.equal(bundle.objects.length, 3);
  for (const obj of bundle.objects) {
    assert.equal(obj.kind, "connector_attestation");
    assert.equal(obj.trust_label, "connector_asserted");
  }
  assert.equal(bundle.checkpoints.length, 1);
});

test("GOLDEN-BUNDLE: the offline verifier (ui/lib/verify-bundle.mjs) accepts the real converted bundle", async () => {
  const { bundle, publicKeys } = buildGwlogBundle(FIXTURE);
  const result = await verifyBundle(bundle, publicKeys);
  assert.equal(result.valid, true, `expected valid bundle, got reasons: ${result.reasons?.join("; ")}`);
});

test("TAMPERED-BUNDLE: a single flipped signature byte is caught by the SAME offline verifier", async () => {
  const { bundle, publicKeys } = buildGwlogBundle(FIXTURE);
  const tampered = structuredClone(bundle);
  // Same tamper shape gen-verify-demo-fixture.mjs proves against: corrupt one
  // sealed object's signature bytes so it fails at the envelope, not the
  // schema — the more convincing failure a real tamper would produce.
  tampered.objects[0].envelope.signatures[0].sig = Buffer.from("not a real signature").toString("base64");

  const result = await verifyBundle(tampered, publicKeys);
  assert.equal(result.valid, false, "tampered bundle must NOT verify");
  assert.ok(
    result.reasons.some((r) => r.startsWith("entry_envelope_invalid")),
    `expected an entry_envelope_invalid reason, got: ${result.reasons?.join("; ")}`
  );
});

test("TAMPERED-BUNDLE: a tampered manifest predicate (trust_label swap) is caught", async () => {
  const { bundle, publicKeys } = buildGwlogBundle(FIXTURE);
  const tampered = structuredClone(bundle);
  tampered.manifest.predicate.entries[0].trust_label = "kernel_verified";

  const result = await verifyBundle(tampered, publicKeys);
  assert.equal(result.valid, false, "bundle with a trust-label-swapped manifest must NOT verify");
});
