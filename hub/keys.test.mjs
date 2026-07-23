import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-keys-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");

test("keys: generated once, reload returns the same key material", async () => {
  const first = loadOrCreateKeys();
  const second = loadOrCreateKeys();
  assert.deepEqual(
    first.ed25519.publicKey.export({ format: "der", type: "spki" }),
    second.ed25519.publicKey.export({ format: "der", type: "spki" })
  );
  assert.deepEqual(first.mldsa44.publicKey, second.mldsa44.publicKey);
});

test("keys: never stored in plaintext on disk", async () => {
  const keys = loadOrCreateKeys();
  const raw = readFileSync(join(TMP, "keys.enc.json"), "utf8");
  const rawBytes = Buffer.from(raw);
  const secretHex = Buffer.from(keys.mldsa44.secretKey).toString("hex").slice(0, 64);
  assert.equal(rawBytes.includes(Buffer.from(secretHex)), false);
  const blob = JSON.parse(raw);
  assert.ok(blob.ciphertext && blob.iv && blob.tag && blob.salt, "expected AEAD envelope fields");
});

test("keys: publicKeysOf() exposes only public material", () => {
  const keys = loadOrCreateKeys();
  const pub = publicKeysOf(keys);
  assert.equal(pub.ed25519.type, "public");
  assert.equal(pub.mldsa44.length, keys.mldsa44.publicKey.length);
  rmSync(TMP, { recursive: true, force: true });
});
