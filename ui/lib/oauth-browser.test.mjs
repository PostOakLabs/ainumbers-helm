import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { liveTest } from "../../test-support/live.mjs";
import {
  generatePkce,
  randomState,
  buildAuthorizationUrl,
  startBrowserFlow,
  loadPendingFlow,
  clearPendingFlow,
  completeBrowserFlow,
  looksLikeFineGrainedPat,
  verifyGithubPat,
  MICROSOFT_SPA,
  GOOGLE_DRIVE_FILE,
} from "./oauth-browser.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.btoa) {
  globalThis.btoa = (str) => Buffer.from(str, "binary").toString("base64");
}

// Minimal storage double matching the Storage interface subset this module
// uses (getItem/setItem/removeItem) — avoids depending on a real
// sessionStorage under node:test.
function memoryStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, v),
    removeItem: (k) => map.delete(k),
  };
}

test("generatePkce: verifier/challenge are S256-linked and change every call", async () => {
  const a = await generatePkce();
  const b = await generatePkce();
  assert.notEqual(a.codeVerifier, b.codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(a.codeVerifier));
  const expected = Buffer.from(digest).toString("base64url");
  assert.equal(a.codeChallenge, expected);
});

test("randomState: hex string of the requested byte length, changes every call", () => {
  const s1 = randomState(crypto, 16);
  const s2 = randomState(crypto, 16);
  assert.equal(s1.length, 32);
  assert.match(s1, /^[0-9a-f]+$/);
  assert.notEqual(s1, s2);
});

test("buildAuthorizationUrl: MS preset carries response_type=code + PKCE S256", () => {
  const url = new URL(
    buildAuthorizationUrl({
      authorizationEndpoint: MICROSOFT_SPA.authorizationEndpoint(),
      clientId: "client-1",
      redirectUri: "https://ainumbers.co/helm/oauth-callback.html",
      scopes: MICROSOFT_SPA.defaultScopes,
      state: "st-1",
      codeChallenge: "chal-1",
    })
  );
  assert.equal(url.origin + url.pathname, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("client_id"), "client-1");
  assert.equal(url.searchParams.get("scope"), "offline_access Files.Read");
});

test("buildAuthorizationUrl: Google preset requests drive.file only, never a broader scope", () => {
  const url = new URL(
    buildAuthorizationUrl({
      authorizationEndpoint: GOOGLE_DRIVE_FILE.authorizationEndpoint,
      clientId: "client-2",
      redirectUri: "https://ainumbers.co/helm/oauth-callback.html",
      scopes: GOOGLE_DRIVE_FILE.defaultScopes,
      state: "st-2",
      codeChallenge: "chal-2",
    })
  );
  assert.equal(url.searchParams.get("scope"), "https://www.googleapis.com/auth/drive.file");
});

test("buildAuthorizationUrl: rejects a missing clientId/redirectUri", () => {
  assert.throws(
    () => buildAuthorizationUrl({ authorizationEndpoint: "https://example.com/authorize", redirectUri: "https://x", scopes: [], state: "s", codeChallenge: "c" }),
    /clientId/
  );
  assert.throws(
    () => buildAuthorizationUrl({ authorizationEndpoint: "https://example.com/authorize", clientId: "c1", scopes: [], state: "s", codeChallenge: "c" }),
    /redirectUri/
  );
});

test("startBrowserFlow -> completeBrowserFlow: full PKCE round trip against a mock token endpoint", async () => {
  const storage = memoryStorage();
  const { authorizationUrl, state } = await startBrowserFlow({
    provider: "google",
    authorizationEndpoint: GOOGLE_DRIVE_FILE.authorizationEndpoint,
    clientId: "client-3",
    redirectUri: "https://ainumbers.co/helm/oauth-callback.html",
    scopes: GOOGLE_DRIVE_FILE.defaultScopes,
    storage,
  });
  assert.match(authorizationUrl, /^https:\/\/accounts\.google\.com\/o\/oauth2\/v2\/auth\?/);
  assert.ok(loadPendingFlow("google", storage), "pending flow persisted");

  let seenBody = null;
  const fetchImpl = async (url, opts) => {
    seenBody = new URLSearchParams(opts.body);
    return { ok: true, json: async () => ({ access_token: "at-123", token_type: "Bearer" }) };
  };

  const tokens = await completeBrowserFlow({
    provider: "google",
    code: "auth-code-1",
    state,
    tokenEndpoint: GOOGLE_DRIVE_FILE.tokenEndpoint,
    fetchImpl,
    storage,
  });

  assert.equal(tokens.access_token, "at-123");
  assert.equal(seenBody.get("grant_type"), "authorization_code");
  assert.equal(seenBody.get("code"), "auth-code-1");
  assert.equal(seenBody.get("client_id"), "client-3");
  assert.ok(seenBody.get("code_verifier"), "PKCE verifier sent to the token endpoint");
  assert.equal(loadPendingFlow("google", storage), null, "flow consumed after completion");
});

test("completeBrowserFlow: rejects a state mismatch and clears the pending flow", async () => {
  const storage = memoryStorage();
  await startBrowserFlow({
    provider: "microsoft",
    authorizationEndpoint: MICROSOFT_SPA.authorizationEndpoint(),
    clientId: "client-4",
    redirectUri: "https://ainumbers.co/helm/oauth-callback.html",
    scopes: MICROSOFT_SPA.defaultScopes,
    storage,
  });

  await assert.rejects(
    () => completeBrowserFlow({ provider: "microsoft", code: "c", state: "wrong-state", tokenEndpoint: () => "https://x", fetchImpl: async () => ({ ok: true, json: async () => ({}) }), storage }),
    /state mismatch/
  );
  assert.equal(loadPendingFlow("microsoft", storage), null);
});

test("completeBrowserFlow: no pending flow at all is a clear error, not a crash", async () => {
  const storage = memoryStorage();
  await assert.rejects(
    () => completeBrowserFlow({ provider: "github", code: "c", state: "s", tokenEndpoint: "https://x", storage }),
    /no pending github flow/
  );
});

test("clearPendingFlow: idempotent", () => {
  const storage = memoryStorage();
  clearPendingFlow("google", storage);
  assert.equal(loadPendingFlow("google", storage), null);
});

test("looksLikeFineGrainedPat: shape check only", () => {
  assert.equal(looksLikeFineGrainedPat("github_pat_11ABCDEFG0123456789012345"), true);
  assert.equal(looksLikeFineGrainedPat("ghp_classicToken1234567890"), false);
  assert.equal(looksLikeFineGrainedPat(""), false);
  assert.equal(looksLikeFineGrainedPat(null), false);
});

test("verifyGithubPat: reports failure on a non-ok response without throwing", async () => {
  const fetchImpl = async () => ({ ok: false, status: 401 });
  const result = await verifyGithubPat("github_pat_bad", fetchImpl);
  assert.deepEqual(result, { ok: false, status: 401 });
});

// Live where free (PR notes call this out per the WU brief) — real GitHub
// API call, no app registration needed, kept out of the blocking suite.
liveTest("verifyGithubPat: LIVE — a garbage token is rejected by the real API", async () => {
  const result = await verifyGithubPat("github_pat_not_a_real_token_00000000000000000000000000");
  assert.equal(result.ok, false);
});
