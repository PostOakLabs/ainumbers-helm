// SIGN-PREROT-1 phil-(d) done-criterion: continuity verification runs OFFLINE
// in the shipped bundle verifier. Chains are built with the DAEMON-side
// signer (hub/key-lifecycle.mjs, node:crypto) and verified with the
// BROWSER-side reader (this module's WebCrypto path) — the exact split a
// real bundle crosses (helmd signs, the standalone HTML verifier reads),
// proving the two never silently diverge on what counts as valid.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateLifecycleKeyPair,
  buildInceptionEvent,
  buildRotationEvent,
} from "../../hub/key-lifecycle.mjs";
import { verifyKeyLineage } from "./verify-key-lineage.mjs";

function goldenChain() {
  const key0 = generateLifecycleKeyPair();
  const key1 = generateLifecycleKeyPair();
  const key2 = generateLifecycleKeyPair();
  const inception = buildInceptionEvent({ identityId: "browser-1", currentKeys: key0, nextPublicKey: key1.publicKey });
  const rot1 = buildRotationEvent({ identityId: "browser-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: key2.publicKey });
  const rot2 = buildRotationEvent({ identityId: "browser-1", identitySeq: 2, priorEnvelope: rot1, revealedKeys: key2, nextPublicKey: generateLifecycleKeyPair().publicKey });
  return { key0, key1, key2, inception, rot1, rot2 };
}

test("offline bundle verifier: golden chain (Node-signed) verifies fully via WebCrypto, no network", async () => {
  const { inception, rot1, rot2, key2 } = goldenChain();
  const result = await verifyKeyLineage([inception, rot1, rot2]);
  assert.equal(result.status, "continuous");
  assert.equal(result.headSeq, 2);
  assert.equal(result.currentPublicKeyB64, key2.publicKey.export({ format: "der", type: "spki" }).toString("base64"));
});

test("offline bundle verifier: TAMPERED chain (flipped byte in a rotation signature) is caught", async () => {
  const { inception, rot1, rot2 } = goldenChain();
  const tamperedSig = Buffer.from(rot1.signatures[0].sig, "base64");
  tamperedSig[0] ^= 0xff;
  const tamperedRot1 = { ...rot1, signatures: [{ ...rot1.signatures[0], sig: tamperedSig.toString("base64") }] };
  const result = await verifyKeyLineage([inception, tamperedRot1, rot2]);
  assert.equal(result.status, "invalid");
  assert.equal(result.reason, "revealed_key_signature_invalid");
});

test("offline bundle verifier: a rotation whose revealed key doesn't match the commitment is caught", async () => {
  const { inception } = goldenChain();
  const wrongKey = generateLifecycleKeyPair();
  const badRotation = buildRotationEvent({ identityId: "browser-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: wrongKey, nextPublicKey: generateLifecycleKeyPair().publicKey });
  const result = await verifyKeyLineage([inception, badRotation]);
  assert.equal(result.status, "invalid");
  assert.equal(result.reason, "commitment_mismatch");
});

test("offline bundle verifier: fork (two rotations off the same commitment) is detected and flagged, not resolved", async () => {
  const { key1, inception } = goldenChain();
  const branchA = buildRotationEvent({ identityId: "browser-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: generateLifecycleKeyPair().publicKey });
  const branchB = buildRotationEvent({ identityId: "browser-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: generateLifecycleKeyPair().publicKey, createdAt: "2099-01-01T00:00:00.000Z" });
  const result = await verifyKeyLineage([inception, branchA, branchB]);
  assert.equal(result.status, "fork_detected");
  assert.equal(result.competing.length, 2);
});

test("offline bundle verifier: no network access is reachable from this module (no fetch/XHR imports)", async () => {
  const src = await (await import("node:fs/promises")).readFile(new URL("./verify-key-lineage.mjs", import.meta.url), "utf8");
  assert.ok(!/\bfetch\(|XMLHttpRequest/.test(src), "verify-key-lineage.mjs must stay zero-network");
});
