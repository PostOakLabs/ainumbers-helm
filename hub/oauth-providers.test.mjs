// Proves the GitHub preset's endpoint/scope shape round-trips through the
// SAME shared PKCE loopback flow (oauth-pkce.mjs startFlow, already
// R1/SEC-reviewed and grep-gated by vault-secret-gate.test.mjs) — the
// sandboxed test runner can't reach github.com, so authorizationEndpoint/
// tokenEndpoint are overridden to a local mock; beginGithubFlowParams()
// otherwise supplies GitHub's real endpoint constants unmodified.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-oauth-providers-test-"));
process.env.HELM_HOME = TMP;

const { startFlow, getFlowStatus } = await import("./oauth-pkce.mjs");
const { GITHUB, beginGithubFlowParams } = await import("./oauth-providers.mjs");

function b64url(buf) {
  return buf.toString("base64url");
}

test("oauth-providers: GITHUB preset carries the real endpoint constants", () => {
  assert.equal(GITHUB.provider, "github");
  assert.equal(GITHUB.authorizationEndpoint, "https://github.com/login/oauth/authorize");
  assert.equal(GITHUB.tokenEndpoint, "https://github.com/login/oauth/access_token");
  assert.throws(() => beginGithubFlowParams({}), /clientId/);
});

test("oauth-providers: beginGithubFlowParams() completes a full PKCE loopback flow against a mock GitHub", async () => {
  const codes = new Map();
  const mockGithub = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname === "/authorize") {
      const code = randomBytes(12).toString("hex");
      codes.set(code, url.searchParams.get("code_challenge"));
      const redirect = new URL(url.searchParams.get("redirect_uri"));
      redirect.searchParams.set("code", code);
      redirect.searchParams.set("state", url.searchParams.get("state"));
      res.writeHead(302, { Location: redirect.toString() });
      return res.end();
    }
    if (url.pathname === "/access_token" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        // Real GitHub replies form-urlencoded unless Accept: application/json
        // is sent — proves oauth-pkce.mjs's exchangeCode() sends it.
        assert.equal(req.headers.accept, "application/json");
        const params = new URLSearchParams(body);
        const challenge = codes.get(params.get("code"));
        const expected = b64url(createHash("sha256").update(params.get("code_verifier")).digest());
        if (expected !== challenge) {
          res.writeHead(400);
          return res.end("{}");
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "gh-token-abc", token_type: "bearer" }));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => mockGithub.listen(0, "127.0.0.1", resolve));
  const mockBase = `http://127.0.0.1:${mockGithub.address().port}`;

  try {
    const params = beginGithubFlowParams({
      clientId: "test-github-client",
      authorizationEndpoint: `${mockBase}/authorize`,
      tokenEndpoint: `${mockBase}/access_token`,
    });
    assert.equal(params.provider, "github");
    assert.deepEqual(params.scopes, GITHUB.defaultScopes);

    const { flowId, authorizationUrl } = await startFlow(params);
    await fetch(authorizationUrl);

    const start = Date.now();
    while (Date.now() - start < 2000) {
      if (getFlowStatus(flowId).status === "complete") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(getFlowStatus(flowId).status, "complete");
  } finally {
    mockGithub.close();
  }
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
