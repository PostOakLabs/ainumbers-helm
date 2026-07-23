import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-envelope-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { buildStatement, emitEnvelope, verifyEnvelope, helmPredicateType } = await import("./envelope.mjs");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);

function sampleStatement() {
  return buildStatement({
    subject: [{ name: "test-artifact", digest: { sha256: "a".repeat(64) } }],
    predicateType: helmPredicateType("test"),
    predicate: { note: "HELM-H2 fixture" },
  });
}

test("envelope: dual-signed emit + verify round-trips clean", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const result = verifyEnvelope(envelope, publicKeys);
  assert.equal(result.valid, true);
  assert.equal(result.ed25519, true);
  assert.equal(result.mldsa44, true);
  assert.equal(result.statement.predicate.note, "HELM-H2 fixture");
});

test("negative: tampered payload fails both signature families", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const tampered = { ...envelope, payload: Buffer.from(JSON.stringify({ tampered: true })).toString("base64") };
  const result = verifyEnvelope(tampered, publicKeys);
  assert.equal(result.valid, false);
  assert.equal(result.ed25519, false);
  assert.equal(result.mldsa44, false);
});

test("negative: tampered Ed25519 signature alone fails the envelope", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const sigs = envelope.signatures.map((s) =>
    s.alg === "EdDSA" ? { ...s, sig: Buffer.from("not a real signature bytes!!").toString("base64") } : s
  );
  const result = verifyEnvelope({ ...envelope, signatures: sigs }, publicKeys);
  assert.equal(result.valid, false);
  assert.equal(result.ed25519, false);
  assert.equal(result.mldsa44, true);
});

test("negative: tampered ML-DSA-44 signature alone fails the envelope (SHOULD co-signature still enforced)", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const sigs = envelope.signatures.map((s) =>
    s.alg === "ML-DSA-44" ? { ...s, sig: Buffer.from(new Uint8Array(2420)).toString("base64") } : s
  );
  const result = verifyEnvelope({ ...envelope, signatures: sigs }, publicKeys);
  assert.equal(result.valid, false);
  assert.equal(result.ed25519, true);
  assert.equal(result.mldsa44, false);
});

test("envelope: missing ML-DSA-44 co-signature still verifies (SHOULD, not MUST)", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const edOnly = { ...envelope, signatures: envelope.signatures.filter((s) => s.alg === "EdDSA") };
  const result = verifyEnvelope(edOnly, publicKeys);
  assert.equal(result.valid, true);
  assert.equal(result.mldsa44, null);
});

test("envelope: strict mode (HELM-SEC-5, F6) rejects a missing ML-DSA-44 co-signature", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const edOnly = { ...envelope, signatures: envelope.signatures.filter((s) => s.alg === "EdDSA") };
  const result = verifyEnvelope(edOnly, publicKeys, { strict: true });
  assert.equal(result.valid, false);
  assert.equal(result.ed25519, true);
  assert.equal(result.mldsa44, null);
});

test("envelope: strict mode still verifies a genuinely dual-signed envelope", () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const result = verifyEnvelope(envelope, publicKeys, { strict: true });
  assert.equal(result.valid, true);
});

// Cross-verify fixture (HELM-H2 contract): a Node-signed envelope must verify
// via the same WebCrypto surface browsers expose (globalThis.crypto.subtle),
// and a WebCrypto-signed payload must verify via the node:crypto path
// envelope.mjs uses — proving the Ed25519 half of the envelope is portable
// browser<->hub. ML-DSA-44 is a pure-JS vendored kernel with no separate
// "browser API" (see art-424 lineage): parity there is inherent, not tested
// here again.
test("cross-verify: Node-signed Ed25519 signature verifies via WebCrypto (browser-context path)", async () => {
  const envelope = emitEnvelope(sampleStatement(), keys);
  const edEntry = envelope.signatures.find((s) => s.alg === "EdDSA");
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  const toVerify = Buffer.concat([
    Buffer.from("DSSEv1 "),
    Buffer.from(`${Buffer.byteLength(envelope.payloadType)} ${envelope.payloadType} ${payloadBytes.length} `),
    payloadBytes,
  ]);

  const spki = publicKeys.ed25519.export({ format: "der", type: "spki" });
  const cryptoKey = await globalThis.crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]);
  const ok = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    cryptoKey,
    Buffer.from(edEntry.sig, "base64"),
    toVerify
  );
  assert.equal(ok, true);
});

test("cross-verify: WebCrypto-signed Ed25519 signature verifies via node:crypto (hub verify path)", async () => {
  const { verify: cryptoVerify } = await import("node:crypto");
  const pkcs8 = keys.ed25519.privateKey.export({ format: "der", type: "pkcs8" });
  const cryptoKey = await globalThis.crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const message = Buffer.from("HELM-H2 cross-verify fixture");
  const sig = Buffer.from(await globalThis.crypto.subtle.sign({ name: "Ed25519" }, cryptoKey, message));

  const ok = cryptoVerify(null, message, publicKeys.ed25519, sig);
  assert.equal(ok, true);
  rmSync(TMP, { recursive: true, force: true });
});
