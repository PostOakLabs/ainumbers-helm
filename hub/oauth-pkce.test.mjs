// Exercises the full RFC 8252 loopback + PKCE flow against an in-repo mock
// OAuth provider (no real connector exists yet — HELM-H5 scope).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-oauth-test-"));
process.env.HELM_HOME = TMP;

const { startFlow, getFlowStatus, listConnections, revokeConnection } = await import("./oauth-pkce.mjs");
const { vaultGet } = await import("./vault.mjs");

// --- Mock OAuth provider: authorize (auto-consents) + token + revoke ---
const codes = new Map(); // code -> { codeChallenge, scope }
const issuedTokens = new Map(); // access_token -> true
const revoked = [];

function b64url(buf) {
  return buf.toString("base64url");
}

const mockProvider = createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname === "/authorize") {
    const code = randomBytes(12).toString("hex");
    codes.set(code, { codeChallenge: url.searchParams.get("code_challenge"), scope: url.searchParams.get("scope") });
    const redirect = new URL(url.searchParams.get("redirect_uri"));
    redirect.searchParams.set("code", code);
    redirect.searchParams.set("state", url.searchParams.get("state"));
    res.writeHead(302, { Location: redirect.toString() });
    return res.end();
  }
  if (url.pathname === "/authorize-error") {
    const redirect = new URL(url.searchParams.get("redirect_uri"));
    redirect.searchParams.set("error", "access_denied");
    redirect.searchParams.set("state", url.searchParams.get("state"));
    res.writeHead(302, { Location: redirect.toString() });
    return res.end();
  }
  if (url.pathname === "/token" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const params = new URLSearchParams(body);
      const entry = codes.get(params.get("code"));
      if (!entry) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "invalid_grant" }));
      }
      const expected = b64url(createHash("sha256").update(params.get("code_verifier")).digest());
      if (expected !== entry.codeChallenge) {
        res.writeHead(400);
        return res.end(JSON.stringify({ error: "invalid_grant", detail: "pkce mismatch" }));
      }
      const accessToken = `at-${randomBytes(8).toString("hex")}`;
      issuedTokens.set(accessToken, true);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: accessToken, refresh_token: `rt-${accessToken}`, token_type: "Bearer", expires_in: 3600 }));
    });
    return;
  }
  if (url.pathname === "/revoke" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const params = new URLSearchParams(body);
      revoked.push(params.get("token"));
      res.writeHead(200);
      res.end();
    });
    return;
  }
  res.writeHead(404);
  res.end();
});

let mockBase;
before(() => new Promise((resolve) => mockProvider.listen(0, "127.0.0.1", () => {
  mockBase = `http://127.0.0.1:${mockProvider.address().port}`;
  resolve();
})));

after(async () => {
  mockProvider.close();
  rmSync(TMP, { recursive: true, force: true });
});

async function waitForStatus(flowId, wantStatus, timeoutMs = 2000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const s = getFlowStatus(flowId);
    if (s.status === wantStatus) return s;
    if (s.status === "error" && wantStatus !== "error") throw new Error(`flow errored: ${s.error}`);
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for status "${wantStatus}", last: ${JSON.stringify(getFlowStatus(flowId))}`);
}

test("full flow: authorize -> callback -> token exchange -> vault + registry", async () => {
  const { flowId, authorizationUrl } = await startFlow({
    provider: "mock",
    authorizationEndpoint: `${mockBase}/authorize`,
    tokenEndpoint: `${mockBase}/token`,
    revocationEndpoint: `${mockBase}/revoke`,
    clientId: "test-client",
    scopes: ["read"],
  });

  // Simulates the system browser: navigating to authorizationUrl follows the
  // provider's redirect straight into our ephemeral loopback callback.
  await fetch(authorizationUrl);

  const status = await waitForStatus(flowId, "complete");
  assert.ok(status.connectionId);

  const conns = listConnections();
  const conn = conns.find((c) => c.id === status.connectionId);
  assert.equal(conn.provider, "mock");
  assert.deepEqual(conn.scopes, ["read"]);
  assert.equal(conn.status, "active");
  assert.equal(conn.vaultRef, undefined, "public view must not leak the vault ref");

  const secret = vaultGet(`helm/oauth/${status.connectionId}`);
  assert.ok(secret.access_token.startsWith("at-"));
});

test("negative: provider error redirect surfaces as flow error", async () => {
  const { flowId, authorizationUrl } = await startFlow({
    provider: "mock",
    authorizationEndpoint: `${mockBase}/authorize-error`,
    tokenEndpoint: `${mockBase}/token`,
    clientId: "test-client",
    scopes: ["read"],
  });
  await fetch(authorizationUrl);
  const status = await waitForStatus(flowId, "error");
  assert.equal(status.error, "access_denied");
});

test("revoke: deletes vault secret, calls provider revocation, marks connection revoked", async () => {
  const { flowId, authorizationUrl } = await startFlow({
    provider: "mock",
    authorizationEndpoint: `${mockBase}/authorize`,
    tokenEndpoint: `${mockBase}/token`,
    revocationEndpoint: `${mockBase}/revoke`,
    clientId: "test-client",
    scopes: ["read", "write"],
  });
  await fetch(authorizationUrl);
  const status = await waitForStatus(flowId, "complete");

  const revokedConn = await revokeConnection(status.connectionId);
  assert.equal(revokedConn.status, "revoked");
  assert.equal(vaultGet(`helm/oauth/${status.connectionId}`), null);
  assert.ok(revoked.length > 0, "provider revocation endpoint should have been called");
});

test("revoke: unknown connection id returns null", async () => {
  assert.equal(await revokeConnection("does-not-exist"), null);
});
