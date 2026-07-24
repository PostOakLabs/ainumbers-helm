import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signChallenge, verifyChallenge, fingerprintPublicKeyDer } from "./challenge.mjs";

function ed25519Pair() {
  return generateKeyPairSync("ed25519");
}

test("signChallenge + verifyChallenge: a genuine challenge verifies", () => {
  const keys = ed25519Pair();
  const challenge = signChallenge(keys);
  assert.equal(verifyChallenge(challenge), true);
});

// Was labeled "a signature from a different keypair fails" — misleading
// (R15-F1): this swaps ONLY the publicKey and keeps the ORIGINAL signature,
// so it fails because the signature no longer matches the swapped-in key —
// a plain signature/publicKey consistency check, nothing about identity. It
// does NOT exercise the real R15-F1 attack: an attacker who signs with
// their OWN key end-to-end (self-consistent) passes this function every
// time — see the squat-triple test below and ui/lib/challenge-browser.test.mjs.
test("verifyChallenge: swapping only the publicKey (signature now mismatched) fails — a consistency check, not identity verification", () => {
  const keys = ed25519Pair();
  const otherKeys = ed25519Pair();
  const challenge = signChallenge(keys);
  const forged = { ...challenge, publicKey: otherKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64") };
  assert.equal(verifyChallenge(forged), false);
});

// R15-F1's actual attack: an attacker mints their own keypair and signs
// consistently end-to-end. verifyChallenge alone has no way to reject this
// — it can only ever prove "the responder holds SOME private key matching
// the publicKey it supplied," never "this is the real daemon's key." Callers
// MUST additionally pin fingerprintPublicKeyDer(publicKey) against a value
// delivered out-of-band (token.mjs pairingUrl's `&fp=`) — see
// ui/lib/challenge-browser.mjs's verifyPinnedChallenge for the wired check.
test("R15-F1 squat-triple: a self-consistent challenge from an attacker's OWN keypair still passes verifyChallenge — proves pinning is required, not optional", () => {
  const attackerKeys = ed25519Pair();
  const squatChallenge = signChallenge(attackerKeys);
  assert.equal(verifyChallenge(squatChallenge), true);
});

test("fingerprintPublicKeyDer: same input, same fingerprint; different keys, different fingerprints", () => {
  const keys = ed25519Pair();
  const der = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.equal(fingerprintPublicKeyDer(der), fingerprintPublicKeyDer(der));
  assert.match(fingerprintPublicKeyDer(der), /^sha256:[0-9a-f]{64}$/);

  const otherKeys = ed25519Pair();
  const otherDer = otherKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  assert.notEqual(fingerprintPublicKeyDer(der), fingerprintPublicKeyDer(otherDer));
});

test("verifyChallenge: a tampered nonce fails even with a valid signature/publicKey pair", () => {
  const keys = ed25519Pair();
  const challenge = signChallenge(keys);
  assert.equal(verifyChallenge({ ...challenge, nonce: challenge.nonce + "x" }), false);
});

test("verifyChallenge: malformed input never throws, just fails", () => {
  assert.equal(verifyChallenge({}), false);
  assert.equal(verifyChallenge({ nonce: "a", signature: "not-base64!!", publicKey: "also-not-base64!!" }), false);
});

test("signChallenge: two challenges from the same keypair carry different nonces (never reused)", () => {
  const keys = ed25519Pair();
  const a = signChallenge(keys);
  const b = signChallenge(keys);
  assert.notEqual(a.nonce, b.nonce);
  assert.equal(a.publicKey, b.publicKey); // same stable identity
});
