// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-PARITY-GATE-1: shared-vector parity gate between the browser Verify
// view's hand-mirrored verifier (ui/lib/verify-envelope.mjs,
// verify-bundle.mjs — see ../vendored/PORT.md's "not a port" note) and the
// hub's own hub/envelope.mjs / hub/bundle.mjs, which it mirrors.
//
// NOT the same gate as verify-vendored-reconcile.test.mjs (that one proves
// ui/vendored/* primitives haven't drifted from their hub source). This one
// proves the two independent, hand-written VERIFIER implementations agree on
// accept/reject + reason for the same signed input — the layer
// verify-vendored-reconcile.test.mjs does not cover. Source:
// research/RESEARCH-HELM-MIRROR-DRIFT-2026-07-25.md (HELM-MIRROR-DRIFT-1).
//
// Two vector sets:
//   PARITY_VECTORS         — hub and ui MUST agree (valid + reasons). A new
//                             disagreement here is a real, unintended drift.
//   EXPECTED_DIVERGENCE_VECTORS — hub and ui are KNOWN to disagree today.
//                             Each entry pins the EXACT verdict on each side;
//                             the test fails if the divergence changes shape
//                             (fixed, worsened, or silently different) so a
//                             real fix updates this file instead of the
//                             divergence going unnoticed either direction.
//                             NEVER `skip`/`todo` these — SO #25/JOB3.
//
// Divergence 1 (`alg` question) is a STANDARDS question, not resolved here —
// see docs/HELM-PARITY-ALG-QUESTION.md for the write-up for a spec ruling.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { verifyEnvelope as uiVerifyEnvelope } from "./verify-envelope.mjs";
import { verifyBundle as uiVerifyBundle } from "./verify-bundle.mjs";

import { buildStatement, emitEnvelope, verifyEnvelope as hubVerifyEnvelope, helmPredicateType } from "../../hub/envelope.mjs";
import { generateKeys, publicKeysOf } from "../../hub/keys.mjs";
import { assembleBundle, verifyBundle as hubVerifyBundle, browserPublicKeys } from "../../hub/bundle.mjs";
import { cgCanon, assertIJson } from "../../hub/vendored/ocg/kernels/_hash.mjs";

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

// Flips one byte of a base64 blob without changing its decoded length, so a
// tampered signature/payload fails verification cleanly on both
// implementations instead of risking a length-mismatch crypto exception
// (Buffer.from(..., "base64") on the hub side, atob() on the ui side both
// decode leniently, but a WRONG-LENGTH signature buffer can make Node's
// crypto.verify() throw instead of returning false — this vector must stay a
// clean fail, not a crash, on both sides).
function corruptOneByte(b64) {
  const buf = Buffer.from(b64, "base64");
  buf[0] = buf[0] ^ 0xff;
  return buf.toString("base64");
}

function freshEnvelope(keys, { subjectName = "step" } = {}) {
  const statement = buildStatement({
    subject: [{ name: subjectName, digest: { sha256: "b".repeat(64) } }],
    predicateType: helmPredicateType("step_result"),
    predicate: { ok: true },
  });
  return emitEnvelope(statement, keys);
}

function withSig(envelope, mutate) {
  return { ...envelope, signatures: envelope.signatures.map((s) => (s.alg === "EdDSA" || s.alg === "Ed25519" ? mutate({ ...s }) : s)) };
}

function checkpointObj(keys, { checkpointSeq = 1, badDigest = false } = {}) {
  const streams = [{ stream_id: "s1", journal_seq: 1, rh: "deadbeef".repeat(4) }];
  const journalRootDigest = jcsDigestHex(streams);
  const predicate = {
    checkpoint_seq: checkpointSeq,
    streams,
    journal_root_digest: badDigest ? "0".repeat(64) : journalRootDigest,
    anchors: [],
  };
  const statement = buildStatement({
    subject: [{ name: "journal_root", digest: { sha256: journalRootDigest } }],
    predicateType: helmPredicateType("checkpoint"),
    predicate,
  });
  const envelope = emitEnvelope(statement, keys);
  return { checkpointSeq, journalRootDigest, envelope };
}

function freshBundle(keys, { checkpoints = [], dropCheckpointsFromArray = false } = {}) {
  const bundle = assembleBundle({
    bundleId: "parity-gate-b1",
    runId: "parity-gate-r1",
    workflowManifestDigest: `sha256:${"a".repeat(64)}`,
    specs: [{ kind: "step_result", subject: [{ name: "step", digest: { sha256: "b".repeat(64) } }], predicate: { ok: true } }],
    checkpoints,
    keys,
  });
  if (dropCheckpointsFromArray) bundle.checkpoints = [];
  return bundle;
}

async function verdictEnvelope(envelope, keys) {
  const hub = hubVerifyEnvelope(envelope, publicKeysOf(keys));
  const ui = await uiVerifyEnvelope(envelope, browserPublicKeys(keys));
  return {
    hub: { valid: hub.valid, ed25519: hub.ed25519, mldsa44: hub.mldsa44 },
    ui: { valid: ui.valid, ed25519: ui.ed25519, mldsa44: ui.mldsa44 },
  };
}

async function verdictBundle(bundle, keys) {
  const hub = hubVerifyBundle(bundle, publicKeysOf(keys));
  const ui = await uiVerifyBundle(bundle, browserPublicKeys(keys));
  return {
    hub: { valid: hub.valid, reasons: [...hub.reasons].sort() },
    ui: { valid: ui.valid, reasons: [...ui.reasons].sort() },
  };
}

// ---------------------------------------------------------------------------
// PARITY_VECTORS — hub and ui MUST produce the identical verdict.
// ---------------------------------------------------------------------------

test("parity: valid double-signed envelope — both accept", async () => {
  const keys = generateKeys();
  const v = await verdictEnvelope(freshEnvelope(keys), keys);
  assert.equal(v.hub.valid, true, "hub");
  assert.equal(v.ui.valid, true, "ui");
  assert.deepEqual(v.hub, v.ui);
});

test("parity: wrong Ed25519 signature bytes — both reject", async () => {
  const keys = generateKeys();
  const tampered = withSig(freshEnvelope(keys), (s) => ({ ...s, sig: corruptOneByte(s.sig) }));
  const v = await verdictEnvelope(tampered, keys);
  assert.equal(v.hub.valid, false, "hub");
  assert.deepEqual(v.hub, v.ui);
});

test("parity: tampered payload (signature unchanged) — both reject", async () => {
  const keys = generateKeys();
  const envelope = freshEnvelope(keys);
  const tampered = { ...envelope, payload: corruptOneByte(envelope.payload) };
  const v = await verdictEnvelope(tampered, keys);
  assert.equal(v.hub.valid, false, "hub");
  assert.deepEqual(v.hub, v.ui);
});

test("parity: unknown alg (neither EdDSA nor Ed25519) — both reject, no ed candidate found", async () => {
  const keys = generateKeys();
  const mutated = withSig(freshEnvelope(keys), (s) => ({ ...s, alg: "BOGUS-ALG" }));
  const v = await verdictEnvelope(mutated, keys);
  assert.equal(v.hub.valid, false, "hub");
  assert.equal(v.hub.ed25519, false);
  assert.deepEqual(v.hub, v.ui);
});

test("parity: bundle referencing a checkpoint digest not present in checkpoints[] — both reject with checkpoint_missing", async () => {
  const keys = generateKeys();
  const cp = checkpointObj(keys);
  const bundle = freshBundle(keys, { checkpoints: [cp], dropCheckpointsFromArray: true });
  const v = await verdictBundle(bundle, keys);
  assert.equal(v.hub.valid, false, "hub");
  assert.equal(v.ui.valid, false, "ui");
  assert.ok(v.hub.reasons.some((r) => r.startsWith("checkpoint_missing:")), `hub reasons: ${v.hub.reasons}`);
  assert.deepEqual(v.hub, v.ui);
});

// ---------------------------------------------------------------------------
// EXPECTED_DIVERGENCE_VECTORS — pinned, known disagreements. Each assertion
// locks the CURRENT shape of the divergence so an accidental change (either
// direction) fails loudly instead of drifting further unnoticed.
// ---------------------------------------------------------------------------

test("expected-divergence 1 (alg question, UNRESOLVED — see docs/HELM-PARITY-ALG-QUESTION.md): alg='Ed25519' — hub rejects (only recognizes 'EdDSA'), ui/browser accepts (recognizes both)", async () => {
  const keys = generateKeys();
  const mutated = withSig(freshEnvelope(keys), (s) => ({ ...s, alg: "Ed25519" }));
  const v = await verdictEnvelope(mutated, keys);
  assert.equal(v.hub.valid, false, "hub must still reject alg='Ed25519' — if this now passes, Divergence 1 is fixed hub-side and this pin must be updated/removed");
  assert.equal(v.hub.ed25519, false);
  assert.equal(v.ui.valid, true, "ui must still accept alg='Ed25519' — if this now fails, Divergence 1 is fixed ui-side and this pin must be updated/removed");
  assert.equal(v.ui.ed25519, true);
});

test("expected-divergence 2 (checkpoint self-consistency, browser-STRICTER): checkpoint envelope valid but journal_root_digest inconsistent with its own streams — hub accepts (verifyBundle only checks the checkpoint's envelope signature), ui/browser rejects (verifyCheckpointOffline recomputes and compares journal_root_digest)", async () => {
  const keys = generateKeys();
  const cp = checkpointObj(keys, { badDigest: true });
  const bundle = freshBundle(keys, { checkpoints: [cp] });
  const v = await verdictBundle(bundle, keys);
  assert.equal(v.hub.valid, true, "hub must still accept an internally-inconsistent-but-validly-signed checkpoint — if this now fails, Divergence 2 is fixed hub-side and this pin must be updated/removed");
  assert.deepEqual(v.hub.reasons, []);
  assert.equal(v.ui.valid, false, "ui must still reject it via journal_root_digest_mismatch — if this now passes, Divergence 2 is fixed ui-side (or regressed) and this pin must be updated/removed");
  assert.ok(v.ui.reasons.some((r) => r.startsWith("checkpoint_envelope_invalid:")), `ui reasons: ${v.ui.reasons}`);
});
