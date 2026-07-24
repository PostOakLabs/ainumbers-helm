import { test } from "node:test";
import assert from "node:assert/strict";

// Only the pure/in-memory exports are covered here (pairingUrl, tokenMatches,
// pairing-nonce lifecycle) — none of them touch statePath, so no HELM_HOME
// fixture dir is needed (unlike keys.test.mjs / doctor.test.mjs).
const { pairingUrl, tokenMatches, createPairingNonce, redeemPairingNonce } = await import("./token.mjs");

test("pairingUrl: with a pair nonce, embeds both token and pair fragment params", () => {
  const url = pairingUrl("tok123", 4173, "nonceABC");
  assert.equal(url, "http://127.0.0.1:4173/#token=tok123&pair=nonceABC");
});

test("pairingUrl: without a pair nonce, omits the pair param (backward compatible)", () => {
  const url = pairingUrl("tok123", 4173);
  assert.equal(url, "http://127.0.0.1:4173/#token=tok123");
});

test("pairingUrl: with a fingerprint, embeds the fp param (R15-F1 fix)", () => {
  const url = pairingUrl("tok123", 4173, "nonceABC", "sha256:deadbeef");
  assert.equal(url, "http://127.0.0.1:4173/#token=tok123&pair=nonceABC&fp=sha256:deadbeef");
});

test("pairingUrl: without a fingerprint, omits the fp param", () => {
  const url = pairingUrl("tok123", 4173, "nonceABC");
  assert.equal(url, "http://127.0.0.1:4173/#token=tok123&pair=nonceABC");
});

test("tokenMatches: correct token matches, wrong token does not", () => {
  assert.equal(tokenMatches("abc", "abc"), true);
  assert.equal(tokenMatches("abc", "xyz"), false);
  assert.equal(tokenMatches("abc", ""), false);
});

test("pairing nonce: single-use — first redeem succeeds, second redeem of the same value fails", () => {
  const nonce = createPairingNonce();
  assert.equal(redeemPairingNonce(nonce), true);
  assert.equal(redeemPairingNonce(nonce), false);
});

test("pairing nonce: unknown nonce is rejected", () => {
  assert.equal(redeemPairingNonce("never-issued"), false);
});

test("pairing nonce: expired (TTL elapsed) is rejected even on its first redeem", () => {
  const mintedAt = Date.now() - 10 * 60 * 1000; // 10 minutes ago, TTL is 5
  const nonce = createPairingNonce(mintedAt);
  assert.equal(redeemPairingNonce(nonce, Date.now()), false);
});

test("pairing nonce: still valid just before TTL expiry", () => {
  const mintedAt = Date.now() - 4 * 60 * 1000; // 4 minutes ago, TTL is 5
  const nonce = createPairingNonce(mintedAt);
  assert.equal(redeemPairingNonce(nonce, Date.now()), true);
});

test("pairing nonce: two nonces are independent — redeeming one never consumes the other", () => {
  const a = createPairingNonce();
  const b = createPairingNonce();
  assert.equal(redeemPairingNonce(a), true);
  assert.equal(redeemPairingNonce(b), true);
});
