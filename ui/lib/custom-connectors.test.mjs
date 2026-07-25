// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// §16.5 refusal cover for HELM-UX2-G-IMPORT: each minimum refusal gets its
// own test, plus §16.4's three-distinct-message contract and §16.6/§16.7's
// presentation/provenance logic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  validateCandidate,
  addCustomConnector,
  hostDisplayParts,
  BUILTIN_CONNECTOR_IDS,
} from "./custom-connectors.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

function fakeLocalStorage() {
  const store = new Map();
  return {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
    clear: () => store.clear(),
  };
}
globalThis.localStorage = fakeLocalStorage();

const VALID = {
  connector_id: "acme.custom-hook",
  connector_version: "1.0.0",
  publisher: "Acme Corp",
  allowed_hosts: ["api.acme.example"],
  allowed_methods: ["GET"],
  scopes: ["read"],
};

test("validateCandidate: parse failure is its own distinct message (§16.4)", async () => {
  const result = await validateCandidate("{ not json");
  assert.equal(result.ok, false);
  assert.equal(result.stage, "parse");
  assert.match(result.message, /Couldn't parse/);
});

test("validateCandidate: schema failure refuses the WHOLE contract, distinct message (§16.5)", async () => {
  const result = await validateCandidate(JSON.stringify({ connector_id: "x" }));
  assert.equal(result.ok, false);
  assert.equal(result.stage, "schema");
  assert.match(result.message, /schema validation/);
});

test("validateCandidate: success is distinct from both failure modes and does not add anything", async () => {
  globalThis.localStorage.clear();
  const result = await validateCandidate(JSON.stringify(VALID));
  assert.equal(result.ok, true);
  assert.equal(result.stage, "preview");
  assert.equal(result.contract.connector_id, "acme.custom-hook");
  assert.match(result.contractDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.parse(globalThis.localStorage.getItem("helm.custom.connectors") ?? "null"), null);
});

test("validateCandidate: refuses a connector_id colliding with a built-in id (§16.5)", async () => {
  for (const id of BUILTIN_CONNECTOR_IDS) {
    const result = await validateCandidate(JSON.stringify({ ...VALID, connector_id: id }));
    assert.equal(result.ok, false, `expected refusal for built-in id "${id}"`);
    assert.equal(result.stage, "collision");
  }
});

test("validateCandidate: refuses a connector_id colliding with a LIVE daemon-served id (§16.5)", async () => {
  const result = await validateCandidate(JSON.stringify({ ...VALID, connector_id: "http.custom-daemon-id" }), {
    knownIds: ["http.custom-daemon-id"],
  });
  assert.equal(result.ok, false);
  assert.equal(result.stage, "collision");
});

test("validateCandidate: refuses __proto__ reaching any merge (§16.5)", async () => {
  // A __proto__ key arriving through JSON TEXT (unlike an object-literal
  // __proto__, which sets the prototype instead) becomes a real own
  // property once JSON.parse'd — schema's additionalProperties:false rejects
  // it as an unknown key, and parseJson's null-prototype re-homing means no
  // downstream spread/Object.assign could act on it as a live accessor
  // either way.
  const hostile = '{"connector_id":"acme.custom-hook","connector_version":"1.0.0","publisher":"Acme Corp","allowed_hosts":["api.acme.example"],"allowed_methods":["GET"],"scopes":["read"],"__proto__":{"polluted":true}}';
  const result = await validateCandidate(hostile);
  assert.equal(result.ok, false);
  assert.equal(result.stage, "schema");
  assert.match(result.message, /__proto__/);
  assert.equal({}.polluted, undefined, "Object.prototype must be untouched");
});

test("addCustomConnector: refuses re-adding the same id twice, distinguishes identical vs edited contract (§16.7)", async () => {
  globalThis.localStorage.clear();
  const first = await validateCandidate(JSON.stringify(VALID));
  addCustomConnector(first);

  const same = await validateCandidate(JSON.stringify(VALID));
  assert.throws(() => addCustomConnector(same), /already added\./);

  const edited = await validateCandidate(JSON.stringify({ ...VALID, allowed_hosts: ["other.example"] }));
  assert.throws(() => addCustomConnector(edited), /DIFFERENT contract/);
});

test("hostDisplayParts: registrable domain is the last two labels, never truncated", () => {
  const { host, registrable, punycode } = hostDisplayParts("mail.api.acme.example");
  assert.equal(host, "mail.api.acme.example");
  assert.equal(registrable, "acme.example");
  assert.equal(punycode, null);
});

test("hostDisplayParts: surfaces the Punycode form for a non-ASCII (IDN homograph) host", () => {
  const { punycode } = hostDisplayParts("аpple.com"); // Cyrillic "а"
  assert.ok(punycode && punycode.startsWith("xn--"), `expected a Punycode form, got ${punycode}`);
});

test("hostDisplayParts: an all-ASCII host is never mistaken for Punycode by case alone", () => {
  const { punycode } = hostDisplayParts("API.Example.com");
  assert.equal(punycode, null);
});
