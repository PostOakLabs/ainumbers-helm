import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { loadContractFromObject, assertEgressAllowed, performEgress } from "./connector-browser.mjs";
import { createMemoryTokenStore, VaultTokenStore } from "./vault-token-store.mjs";
import { generateDek } from "./vault-crypto.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const CONTRACT = {
  connector_id: "google-drive.fetch",
  connector_version: "1.0.0",
  publisher: "ainumbers-helm",
  allowed_hosts: ["www.googleapis.com"],
  allowed_methods: ["GET"],
  scopes: ["drive.file"],
  vault_scope: ["vault://helm/connectors/google-drive/oauth-token"],
};

test("loadContractFromObject: validates against the SAME schema hub/connector.mjs uses, computes a stable digest", async () => {
  const { contract, contractDigest } = await loadContractFromObject(CONTRACT);
  assert.equal(contract.connector_id, "google-drive.fetch");
  assert.match(contractDigest, /^sha256:[0-9a-f]{64}$/);
  const again = await loadContractFromObject(CONTRACT);
  assert.equal(again.contractDigest, contractDigest);
});

test("loadContractFromObject: rejects a contract missing a required field", async () => {
  await assert.rejects(() => loadContractFromObject({ connector_id: "x" }), /connector contract invalid/);
});

test("assertEgressAllowed: host+method must both be in the contract allowlist (mirrors hub/connector.mjs)", async () => {
  const { contract } = await loadContractFromObject(CONTRACT);
  assert.equal(assertEgressAllowed(contract, { host: "www.googleapis.com", method: "GET" }), true);
  assert.equal(assertEgressAllowed(contract, { host: "evil.example.com", method: "GET" }), false);
  assert.equal(assertEgressAllowed(contract, { host: "www.googleapis.com", method: "POST" }), false);
});

test("performEgress: unapproved host is blocked AND reported via onEgress before the throw", async () => {
  const { contract } = await loadContractFromObject(CONTRACT);
  const events = [];
  const fetchImpl = async () => { throw new Error("must not be called"); };

  await assert.rejects(
    () => performEgress({ contract, connectorId: "google-drive.fetch", url: "https://evil.example.com/x", method: "GET", fetchImpl, onEgress: (e) => events.push(e) }),
    /egress blocked/
  );
  assert.equal(events.length, 1);
  assert.equal(events[0].decision, "blocked");
  assert.equal(events[0].destinationHost, "evil.example.com");
});

test("performEgress: allowed host resolves the credential from the tokenStore and attaches Bearer auth", async () => {
  const { contract } = await loadContractFromObject(CONTRACT);
  const store = new VaultTokenStore(generateDek(), createMemoryTokenStore());
  await store.setToken("vault://helm/connectors/google-drive/oauth-token", { access_token: "at-abc" });

  let seenAuth = null;
  const fetchImpl = async (url, opts) => {
    seenAuth = opts.headers.Authorization;
    return { status: 200, headers: { get: () => null }, arrayBuffer: async () => new TextEncoder().encode("hello").buffer, type: "default" };
  };

  const result = await performEgress({
    contract,
    connectorId: "google-drive.fetch",
    url: "https://www.googleapis.com/drive/v3/files/f1?alt=media",
    method: "GET",
    credential: { ref: "vault://helm/connectors/google-drive/oauth-token" },
    tokenStore: store,
    fetchImpl,
  });

  assert.equal(seenAuth, "Bearer at-abc");
  assert.equal(Buffer.from(result.body).toString("utf8"), "hello");
});

test("performEgress: missing tokenStore for a credential-bearing call is a clear error", async () => {
  const { contract } = await loadContractFromObject(CONTRACT);
  await assert.rejects(
    () => performEgress({ contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/x", method: "GET", credential: { ref: "vault://x" }, fetchImpl: async () => ({}) }),
    /no tokenStore given/
  );
});

test("performEgress: re-vets an allowlisted redirect hop, blocks a redirect to a disallowed host", async () => {
  const { contract } = await loadContractFromObject(CONTRACT);
  let calls = 0;
  const fetchImpl = async (url) => {
    calls++;
    if (calls === 1) {
      assert.equal(new URL(url).host, "www.googleapis.com");
      return { status: 302, type: "default", headers: { get: (h) => (h === "location" ? "https://evil.example.com/steal" : null) } };
    }
    throw new Error("must not follow to the disallowed host");
  };
  const events = [];
  await assert.rejects(
    () => performEgress({ contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/redirect-me", method: "GET", fetchImpl, onEgress: (e) => events.push(e) }),
    /egress blocked/
  );
  assert.equal(calls, 1, "the disallowed redirect target must never be fetched");
  assert.equal(events.at(-1).decision, "blocked");
  assert.equal(events.at(-1).destinationHost, "evil.example.com");
});

test("performEgress: an opaque cross-origin redirect (real-browser CORS behavior) fails closed", async () => {
  const { contract } = await loadContractFromObject(CONTRACT);
  const fetchImpl = async () => ({ type: "opaqueredirect", status: 0, headers: { get: () => null } });
  const events = [];
  await assert.rejects(
    () => performEgress({ contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/redirect-me", method: "GET", fetchImpl, onEgress: (e) => events.push(e) }),
    /opaque redirect/
  );
  assert.equal(events[0].decision, "blocked");
});
