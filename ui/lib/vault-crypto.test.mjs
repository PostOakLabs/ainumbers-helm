import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  generateDek,
  randomSalt,
  deriveWrapKeyFromPrf,
  derivePassphraseKdf,
  wrapDek,
  unwrapDek,
  importDek,
  encryptWithDek,
  decryptWithDek,
  bytesToB64,
  b64ToBytes,
  VaultWrongKeyError,
  PBKDF2_ITERATIONS,
} from "./vault-crypto.mjs";

test("generateDek returns 32 random bytes, never the same twice", () => {
  const a = generateDek();
  const b = generateDek();
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, b);
});

test("b64 round trip preserves bytes exactly", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(40));
  assert.deepEqual(b64ToBytes(bytesToB64(bytes)), bytes);
});

test("PRF-derived wrap key: round trip wraps and unwraps the DEK", async () => {
  const prfOutput = crypto.getRandomValues(new Uint8Array(32));
  const dek = generateDek();
  const wrapKey = await deriveWrapKeyFromPrf(prfOutput);
  const wrapped = await wrapDek(dek, wrapKey);
  const unwrapped = await unwrapDek(wrapped, wrapKey);
  assert.deepEqual(unwrapped, dek);
});

test("PRF wrap key is deterministic for the same PRF output, different for different output", async () => {
  const prfOutput = crypto.getRandomValues(new Uint8Array(32));
  const dek = generateDek();
  const keyA = await deriveWrapKeyFromPrf(prfOutput);
  const wrapped = await wrapDek(dek, keyA);

  const keyB = await deriveWrapKeyFromPrf(prfOutput);
  assert.deepEqual(await unwrapDek(wrapped, keyB), dek); // same PRF output -> same key

  const otherPrfOutput = crypto.getRandomValues(new Uint8Array(32));
  const keyC = await deriveWrapKeyFromPrf(otherPrfOutput);
  await assert.rejects(() => unwrapDek(wrapped, keyC), VaultWrongKeyError);
});

test("passphrase KDF: round trip, and wrong passphrase throws VaultWrongKeyError", async () => {
  const dek = generateDek();
  const salt = randomSalt();
  const rightKey = await derivePassphraseKdf("correct horse battery staple", salt);
  const wrapped = await wrapDek(dek, rightKey);
  assert.deepEqual(await unwrapDek(wrapped, rightKey), dek);

  const wrongKey = await derivePassphraseKdf("wrong passphrase", salt);
  await assert.rejects(() => unwrapDek(wrapped, wrongKey), VaultWrongKeyError);
});

test("passphrase KDF uses the OWASP-minimum PBKDF2 iteration count by default", () => {
  assert.equal(PBKDF2_ITERATIONS, 600_000);
});

test("tampered wrapped blob fails to unwrap (GCM auth tag catches it)", async () => {
  const dek = generateDek();
  const prfOutput = crypto.getRandomValues(new Uint8Array(32));
  const key = await deriveWrapKeyFromPrf(prfOutput);
  const wrapped = await wrapDek(dek, key);
  const bytes = b64ToBytes(wrapped);
  bytes[bytes.length - 1] ^= 0xff; // flip a bit in the ciphertext/tag
  const tampered = bytesToB64(bytes);
  await assert.rejects(() => unwrapDek(tampered, key), VaultWrongKeyError);
});

test("encryptWithDek/decryptWithDek round-trips a JSON token payload", async () => {
  const dek = generateDek();
  const dekKey = await importDek(dek);
  const token = { access_token: "at-1", refresh_token: "rt-1", expires_at: 12345 };
  const blob = await encryptWithDek(dekKey, token);
  assert.deepEqual(await decryptWithDek(dekKey, blob), token);
});

test("the DEK never wraps the journal — vault-crypto exposes no journal-shaped API", async () => {
  const exported = Object.keys(await import("./vault-crypto.mjs"));
  for (const name of exported) assert.doesNotMatch(name, /journal/i);
});
