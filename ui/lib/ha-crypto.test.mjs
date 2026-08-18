// Tests for the browser-held §27.2 approver identity (HELM-HA-1). No real
// DOM/localStorage in node:test — same FakeStorage stub as company-profile
// .test.mjs; Node's global webcrypto covers crypto.subtle.
import { test } from "node:test";
import assert from "node:assert/strict";

class FakeStorage {
  #map = new Map();
  getItem(k) { return this.#map.has(k) ? this.#map.get(k) : null; }
  setItem(k, v) { this.#map.set(k, String(v)); }
  removeItem(k) { this.#map.delete(k); }
}
globalThis.localStorage = new FakeStorage();

const { loadOrCreateBrowserIdentity, signHaRecord, signBundleDigest } = await import("./ha-crypto.mjs");
const { verify, didKeyToPublicKey } = await import("../vendored/proof.mjs");

test("loadOrCreateBrowserIdentity: mints a did:key on first use, persists across calls", async () => {
  const a = await loadOrCreateBrowserIdentity();
  assert.match(a.id, /^did:key:z/);
  const b = await loadOrCreateBrowserIdentity();
  assert.equal(b.id, a.id, "second call must reuse the persisted identity, not mint a new one");
});

test("signHaRecord: produces a record that verifies against the signer's own identity.id", async () => {
  const identity = await loadOrCreateBrowserIdentity();
  const record = await signHaRecord(
    { recordType: "approval", role: "approver", subjectHash: "sha256:" + "3".repeat(64), decision: "approve", nowISO: "2026-07-24T12:00:00Z" },
    identity
  );
  assert.equal(record.record_type, "approval");
  assert.equal(record.identity.id, identity.id);
  const publicKey = await didKeyToPublicKey(record.identity.id);
  assert.equal(await verify(record, publicKey), true);
});

test("signHaRecord: a tampered decision fails verification", async () => {
  const identity = await loadOrCreateBrowserIdentity();
  const record = await signHaRecord(
    { recordType: "approval", role: "approver", subjectHash: "sha256:" + "4".repeat(64), decision: "approve", nowISO: "2026-07-24T12:00:00Z" },
    identity
  );
  record.decision = "reject";
  const publicKey = await didKeyToPublicKey(record.identity.id);
  assert.equal(await verify(record, publicKey), false);
});

// HELM-MAKERCHECKER-BUILD-SPEC.md MC-4: the client-side half of the maker
// /checker signing scheme — must round-trip against a raw Ed25519 verify
// (the hub side's verifyBundleDigestSignature does exactly this), never the
// §16 whole-record verify() above (a bundle_digest is not a signed record).
test("signBundleDigest: produces a keyid/sig/alg that verifies with a plain raw Ed25519 check", async () => {
  const identity = await loadOrCreateBrowserIdentity();
  const digest = "sha256:" + "5".repeat(64);
  const signature = await signBundleDigest(identity, digest);
  assert.equal(signature.keyid, identity.id);
  assert.equal(signature.alg, "EdDSA");
  const publicKey = await didKeyToPublicKey(signature.keyid);
  const sigBytes = Uint8Array.from(atob(signature.sig), (c) => c.charCodeAt(0));
  const ok = await crypto.subtle.verify("Ed25519", publicKey, sigBytes, new TextEncoder().encode(digest));
  assert.equal(ok, true);
});

test("signBundleDigest: a signature over a different digest fails verification", async () => {
  const identity = await loadOrCreateBrowserIdentity();
  const signature = await signBundleDigest(identity, "sha256:" + "6".repeat(64));
  const publicKey = await didKeyToPublicKey(signature.keyid);
  const sigBytes = Uint8Array.from(atob(signature.sig), (c) => c.charCodeAt(0));
  const ok = await crypto.subtle.verify("Ed25519", publicKey, sigBytes, new TextEncoder().encode("sha256:" + "7".repeat(64)));
  assert.equal(ok, false);
});
