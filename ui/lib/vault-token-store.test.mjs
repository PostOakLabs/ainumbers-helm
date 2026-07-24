import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { generateDek } from "./vault-crypto.mjs";
import { VaultTokenStore, createMemoryTokenStore } from "./vault-token-store.mjs";

test("setToken/getToken round trip a connector token under the DEK", async () => {
  const dek = generateDek();
  const store = new VaultTokenStore(dek, createMemoryTokenStore());
  const token = { access_token: "at-1", refresh_token: "rt-1", expires_at: 12345 };
  await store.setToken("github", token);
  assert.deepEqual(await store.getToken("github"), token);
});

test("getToken on an unset ref returns null", async () => {
  const store = new VaultTokenStore(generateDek(), createMemoryTokenStore());
  assert.equal(await store.getToken("never-set"), null);
});

test("deleteToken removes the token", async () => {
  const store = new VaultTokenStore(generateDek(), createMemoryTokenStore());
  await store.setToken("ms-graph", { access_token: "at-2" });
  await store.deleteToken("ms-graph");
  assert.equal(await store.getToken("ms-graph"), null);
});

test("the underlying store never sees plaintext — only base64 ciphertext blobs", async () => {
  const raw = createMemoryTokenStore();
  const store = new VaultTokenStore(generateDek(), raw);
  await store.setToken("github", { access_token: "SECRET-PLAINTEXT-CHECK" });
  const blob = await raw.get("github");
  assert.equal(typeof blob, "string");
  assert.doesNotMatch(blob, /SECRET-PLAINTEXT-CHECK/);
});

test("a token store built from a different DEK cannot decrypt another store's tokens", async () => {
  const memStore = createMemoryTokenStore();
  const storeA = new VaultTokenStore(generateDek(), memStore);
  await storeA.setToken("github", { access_token: "at-1" });

  const storeB = new VaultTokenStore(generateDek(), memStore); // different DEK, same backing store
  await assert.rejects(() => storeB.getToken("github"));
});
