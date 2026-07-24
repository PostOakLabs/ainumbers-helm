import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { signChallenge, verifyChallenge } from "./challenge.mjs";

function ed25519Pair() {
  return generateKeyPairSync("ed25519");
}

test("signChallenge + verifyChallenge: a genuine challenge verifies", () => {
  const keys = ed25519Pair();
  const challenge = signChallenge(keys);
  assert.equal(verifyChallenge(challenge), true);
});

test("verifyChallenge: a signature from a different keypair fails", () => {
  const keys = ed25519Pair();
  const otherKeys = ed25519Pair();
  const challenge = signChallenge(keys);
  const forged = { ...challenge, publicKey: otherKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64") };
  assert.equal(verifyChallenge(forged), false);
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
