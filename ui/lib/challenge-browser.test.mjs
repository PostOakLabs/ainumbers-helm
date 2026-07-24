import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign, randomBytes, createHash } from "node:crypto";
import { verifyChallenge, fingerprintPublicKeyDer, verifyPinnedChallenge } from "./challenge-browser.mjs";

// Node-side signer standing in for hub/challenge.mjs's signChallenge — this
// module only ever verifies (it runs in the browser), so tests mint
// challenges the same way the daemon does.
function signChallenge(ed25519Keys) {
  const nonce = randomBytes(16).toString("base64url");
  const signature = cryptoSign(null, Buffer.from(nonce, "utf8"), ed25519Keys.privateKey).toString("base64");
  const publicKey = ed25519Keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  return { nonce, signature, publicKey };
}

function ed25519Pair() {
  return generateKeyPairSync("ed25519");
}

test("verifyChallenge: a genuine challenge verifies", async () => {
  const keys = ed25519Pair();
  const challenge = signChallenge(keys);
  assert.equal(await verifyChallenge(challenge), true);
});

test("verifyChallenge: malformed input never throws, just fails", async () => {
  assert.equal(await verifyChallenge({}), false);
  assert.equal(await verifyChallenge({ nonce: "a", signature: "not-base64!!", publicKey: "also-not-base64!!" }), false);
});

test("fingerprintPublicKeyDer: matches the daemon-side algorithm (sha256 over raw SPKI DER bytes)", async () => {
  const keys = ed25519Pair();
  const der = keys.publicKey.export({ format: "der", type: "spki" });
  const expected = `sha256:${createHash("sha256").update(der).digest("hex")}`;
  const got = await fingerprintPublicKeyDer(der.toString("base64"));
  assert.equal(got, expected);
});

// --- The squat-triple: R15-F1's core attack, and why verifyChallenge alone
// (self-consistency only) can never catch it. ---

test("R15-F1 squat-triple: a port squatter's OWN keypair, self-consistently signed, PASSES verifyChallenge — this is the exact gap pinning must close", async () => {
  const squatterKeys = ed25519Pair();
  const squatChallenge = signChallenge(squatterKeys);
  assert.equal(await verifyChallenge(squatChallenge), true, "self-consistency alone cannot distinguish a squatter from the real daemon");
});

test("verifyPinnedChallenge: the SAME squat-triple is REJECTED once pinned against the real daemon's out-of-band fingerprint", async () => {
  const realDaemonKeys = ed25519Pair();
  const realFp = await fingerprintPublicKeyDer(realDaemonKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64"));

  const squatterKeys = ed25519Pair();
  const squatChallenge = signChallenge(squatterKeys); // self-consistent, would pass verifyChallenge alone

  const result = await verifyPinnedChallenge(squatChallenge, realFp, 5000);
  assert.equal(result, null);
});

test("verifyPinnedChallenge: a genuine daemon challenge matching the pinned fingerprint is accepted and carries verifiedAt", async () => {
  const realDaemonKeys = ed25519Pair();
  const realFp = await fingerprintPublicKeyDer(realDaemonKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64"));
  const challenge = signChallenge(realDaemonKeys);

  const result = await verifyPinnedChallenge(challenge, realFp, 5000);
  assert.ok(result);
  assert.equal(result.fingerprint, realFp);
  assert.equal(result.verifiedAt, 5000);
});

test("verifyPinnedChallenge: refuses with no pinned fingerprint at all (never falls back to trusting an unpinned challenge)", async () => {
  const keys = ed25519Pair();
  const challenge = signChallenge(keys);
  assert.equal(await verifyPinnedChallenge(challenge, null), null);
  assert.equal(await verifyPinnedChallenge(challenge, undefined), null);
});

test("verifyPinnedChallenge: refuses a badly-signed challenge even if its publicKey happens to match the pin (fingerprint match is necessary, not sufficient)", async () => {
  const keys = ed25519Pair();
  const fp = await fingerprintPublicKeyDer(keys.publicKey.export({ format: "der", type: "spki" }).toString("base64"));
  const genuine = signChallenge(keys);
  const tampered = { ...genuine, nonce: genuine.nonce + "x" };
  assert.equal(await verifyPinnedChallenge(tampered, fp), null);
});
