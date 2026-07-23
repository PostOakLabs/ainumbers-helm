import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-credprovider-test-"));
process.env.HELM_HOME = TMP;

const { vaultSet } = await import("./vault.mjs");
const { attachCredential, credentialExists } = await import("./credential-provider.mjs");

test("attachCredential: bearer scheme resolves the vault ref into an Authorization header", () => {
  const { ref } = vaultSet("test:bearer-token", { access_token: "at-secret-1" });
  const headers = attachCredential({ "X-Existing": "kept" }, { ref, scheme: "bearer" });
  assert.equal(headers.Authorization, "Bearer at-secret-1");
  assert.equal(headers["X-Existing"], "kept");
});

test("attachCredential: basic scheme builds a base64 user:pass header", () => {
  const { ref } = vaultSet("test:basic-creds", { username: "svc", password: "pw-secret-2" });
  const headers = attachCredential({}, { ref, scheme: "basic" });
  assert.equal(headers.Authorization, `Basic ${Buffer.from("svc:pw-secret-2").toString("base64")}`);
});

test("attachCredential: api-key-header scheme sets the named header", () => {
  const { ref } = vaultSet("test:api-key", { api_key: "key-secret-3" });
  const headers = attachCredential({}, { ref, scheme: "api-key-header", header: "X-Api-Key" });
  assert.equal(headers["X-Api-Key"], "key-secret-3");
});

test("attachCredential: unknown ref throws rather than silently omitting auth", () => {
  assert.throws(() => attachCredential({}, { ref: "no-such-ref", scheme: "bearer" }), /no secret stored/);
});

test("attachCredential: unknown scheme throws", () => {
  const { ref } = vaultSet("test:scheme-check", { access_token: "at-secret-4" });
  assert.throws(() => attachCredential({}, { ref, scheme: "totally-unknown" }), /unknown scheme/);
});

test("credentialExists: true only when the ref actually resolves, never returns the secret", () => {
  const { ref } = vaultSet("test:presence-check", { access_token: "at-secret-5" });
  assert.equal(credentialExists(ref), true);
  assert.equal(credentialExists("nonexistent-ref"), false);
  assert.equal(credentialExists(undefined), false);
});

// Grep-gate (mirrors vault-secret-gate.test.mjs): the resolved secret value
// must never appear in this test file's own captured console output — it
// should only ever flow into a returned headers object, never get logged.
test("grep-gate: attachCredential never writes the secret value to stdout/stderr", () => {
  const MARKER = "SECRET-MARKER-CREDPROVIDER-9f3a1c";
  const { ref } = vaultSet("test:grep-gate", { access_token: MARKER });

  const captured = [];
  const originalOut = process.stdout.write.bind(process.stdout);
  const originalErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = (chunk, ...rest) => { captured.push(chunk.toString()); return originalOut(chunk, ...rest); };
  process.stderr.write = (chunk, ...rest) => { captured.push(chunk.toString()); return originalErr(chunk, ...rest); };

  let headers;
  try {
    headers = attachCredential({}, { ref, scheme: "bearer" });
    console.log("credential-provider grep-gate: attached, mentioning nothing secret");
  } finally {
    process.stdout.write = originalOut;
    process.stderr.write = originalErr;
  }

  assert.equal(headers.Authorization, `Bearer ${MARKER}`);
  for (const line of captured) {
    assert.doesNotMatch(line, new RegExp(MARKER), `credential leaked into stdout/stderr: ${line}`);
  }
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
