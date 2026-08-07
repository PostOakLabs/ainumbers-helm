// SIGN-PREROT-1 done-criteria tests (SIGNING-SURFACES-BUILD-SPEC.md §2, phil's
// test list). Each negative case is the actual attack phil named: a rotation
// event not signed by the pre-committed key, a revealed key that doesn't
// match its recorded commitment, a replayed/stale rotation trying to roll
// the identity back, and two competing rotations forking the same commitment.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  generateLifecycleKeyPair,
  buildInceptionEvent,
  buildRotationEvent,
  verifyKeyLineage,
  assertRotationAppendable,
  commitmentOf,
  eventDigest,
} from "./key-lifecycle.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";

const KEY_EVENT_SCHEMA = JSON.parse(readFileSync(new URL("../schema/key_lifecycle_event.schema.json", import.meta.url)));

function chain3() {
  const key0 = generateLifecycleKeyPair();
  const key1 = generateLifecycleKeyPair();
  const key2 = generateLifecycleKeyPair();
  const inception = buildInceptionEvent({ identityId: "id-1", currentKeys: key0, nextPublicKey: key1.publicKey });
  const rot1 = buildRotationEvent({
    identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: key2.publicKey,
  });
  const rot2 = buildRotationEvent({
    identityId: "id-1", identitySeq: 2, priorEnvelope: rot1, revealedKeys: key2, nextPublicKey: generateLifecycleKeyPair().publicKey,
  });
  return { key0, key1, key2, inception, rot1, rot2 };
}

test("happy path: inception + two rotations verify as one continuous chain", () => {
  const { inception, rot1, rot2, key2 } = chain3();
  const result = verifyKeyLineage([inception, rot1, rot2]);
  assert.equal(result.status, "continuous");
  assert.equal(result.headSeq, 2);
  assert.equal(result.currentPublicKeyB64, key2.publicKey.export({ format: "der", type: "spki" }).toString("base64"));
});

test("partial chain (inception + one rotation) verifies as continuous up to that head", () => {
  const { inception, rot1 } = chain3();
  const result = verifyKeyLineage([inception, rot1]);
  assert.equal(result.status, "continuous");
  assert.equal(result.headSeq, 1);
});

// --- phil (a): rotation-replay rejected -----------------------------------

test("REPLAY: an old rotation cannot be appended once the head has moved past it", () => {
  const { inception, rot1, rot2 } = chain3();
  const headAfterRot2 = { digest: eventDigest(rot2), seq: 2, commitment: JSON.parse(Buffer.from(rot2.payload, "base64").toString()).next_key_commitment };
  assert.throws(() => assertRotationAppendable(headAfterRot2, rot1), /rejected/);
});

test("REPLAY: resubmitting the exact same already-applied rotation is a no-op, not a fork", () => {
  // Byte-identical duplicate (a benign resend/retry) must NOT be mistaken for
  // a second competing branch — verifyKeyLineage dedupes by digest before
  // fork-checking (see the "Dedupe by digest" comment in the implementation).
  const { inception, rot1, rot2 } = chain3();
  const result = verifyKeyLineage([inception, rot1, rot1, rot2]);
  assert.equal(result.status, "continuous");
  assert.equal(result.headSeq, 2);
});

test("REPLAY-AS-FORK: a rollback attempt built from an already-superseded key is caught by fork detection", () => {
  // A rollback attempt IS a fork under this design: redeeming an already-
  // consumed commitment a second time — whether the motive is malice
  // (rolling the identity back to a leaked old key) or an honest double-sign
  // — collides with the real successor at the same prev_event_digest and is
  // refused exactly like any other equivocation (see FORK test below).
  const { key1, inception, rot1 } = chain3();
  const rollback = buildRotationEvent({
    identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: generateLifecycleKeyPair().publicKey,
  });
  const result = verifyKeyLineage([inception, rot1, rollback]);
  assert.equal(result.status, "fork_detected");
});

// --- phil (b): post-rotation fork detected, adjudication refused ----------

test("FORK: two competing rotations off the same commitment are both flagged, neither wins", () => {
  const { key1, inception } = chain3();
  const branchA = buildRotationEvent({
    identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: generateLifecycleKeyPair().publicKey,
  });
  const branchB = buildRotationEvent({
    identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: generateLifecycleKeyPair().publicKey,
    createdAt: "2099-01-01T00:00:00.000Z",
  });
  const result = verifyKeyLineage([inception, branchA, branchB]);
  assert.equal(result.status, "fork_detected");
  assert.equal(result.competing.length, 2);
  assert.ok(result.competing.includes(eventDigest(branchA)));
  assert.ok(result.competing.includes(eventDigest(branchB)));
});

// --- phil (c): SHA-256 only, no digest agility -----------------------------

test("commitment is always a sha256: URI with a 64-hex-char digest", () => {
  const key = generateLifecycleKeyPair();
  const commitment = commitmentOf(key.publicKey);
  assert.match(commitment, /^sha256:[0-9a-f]{64}$/);
});

// --- signature / commitment integrity --------------------------------------

test("rotation NOT signed by the pre-committed key is rejected, even though it correctly names that key", () => {
  const { inception, key1 } = chain3();
  const impostor = generateLifecycleKeyPair();
  // Claims revealed_public_key = key1 (which DOES match inception's
  // commitment) but the "revealed" signature slot is actually signed by an
  // impostor keypair — i.e. someone who knows key1's PUBLIC half (public by
  // definition) but not its private key, trying to forge the reveal.
  const genuine = buildRotationEvent({
    identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: generateLifecycleKeyPair().publicKey,
  });
  const forgedSig = { ...genuine, signatures: [{ label: "revealed", alg: "EdDSA", sig: buildRotationEvent({ identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: impostor, nextPublicKey: generateLifecycleKeyPair().publicKey }).signatures[0].sig }] };
  const result = verifyKeyLineage([inception, forgedSig]);
  assert.equal(result.status, "invalid");
  assert.equal(result.reason, "revealed_key_signature_invalid");
});

test("a revealed key that does not match the recorded commitment fails even with a valid signature", () => {
  const { inception } = chain3();
  const wrongKey = generateLifecycleKeyPair(); // never committed to by inception
  const badRotation = buildRotationEvent({
    identityId: "id-1", identitySeq: 1, priorEnvelope: inception, revealedKeys: wrongKey, nextPublicKey: generateLifecycleKeyPair().publicKey,
  });
  const result = verifyKeyLineage([inception, badRotation]);
  assert.equal(result.status, "invalid");
  assert.equal(result.reason, "commitment_mismatch");
});

test("chain not starting at inception is invalid", () => {
  const { rot1 } = chain3();
  const result = verifyKeyLineage([rot1]);
  assert.equal(result.status, "invalid");
});

// --- schema conformance (schema/key_lifecycle_event.schema.json) ----------

test("built inception + rotation envelopes conform to the committed schema", () => {
  const { inception, rot1 } = chain3();
  assert.deepEqual(validate(KEY_EVENT_SCHEMA, inception), []);
  assert.deepEqual(validate(KEY_EVENT_SCHEMA, rot1), []);
  const inceptionPayloadErrs = validate(KEY_EVENT_SCHEMA.$defs.inceptionPayload, JSON.parse(Buffer.from(inception.payload, "base64").toString()), KEY_EVENT_SCHEMA);
  assert.deepEqual(inceptionPayloadErrs, []);
  const rotationPayloadErrs = validate(KEY_EVENT_SCHEMA.$defs.rotationPayload, JSON.parse(Buffer.from(rot1.payload, "base64").toString()), KEY_EVENT_SCHEMA);
  assert.deepEqual(rotationPayloadErrs, []);
});

test("optional outgoing-key co-signature is accepted and does not change validity", () => {
  const key0 = generateLifecycleKeyPair();
  const key1 = generateLifecycleKeyPair();
  const key2 = generateLifecycleKeyPair();
  const inception = buildInceptionEvent({ identityId: "id-2", currentKeys: key0, nextPublicKey: key1.publicKey });
  const rot1 = buildRotationEvent({
    identityId: "id-2", identitySeq: 1, priorEnvelope: inception, revealedKeys: key1, nextPublicKey: key2.publicKey, outgoingPrivateKey: key0.privateKey,
  });
  assert.equal(rot1.signatures.length, 2);
  const result = verifyKeyLineage([inception, rot1]);
  assert.equal(result.status, "continuous");
});
