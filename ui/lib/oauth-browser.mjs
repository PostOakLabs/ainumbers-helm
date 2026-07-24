// Browser-side OAuth (HELM-P3-U4, HELM-PHASE3-BUILD-SPEC.md P3-D5). Runs
// entirely client-side against SPA-registered apps: Microsoft's identity
// platform (redirect-URI type "Single-page application") and Google's OAuth
// endpoint (public/PKCE client, no client secret, CORS-enabled since 2022)
// both let a static page exchange an authorization code for tokens with a
// plain fetch() — no server hop needed, matching the P3-D3 "handoff-first,
// $0 budget" architecture.
//
// Microsoft SPA registration carries a hard platform cap: refresh tokens
// issued to a SPA client are valid ~24h (vs. helmd's separate native/public
// client registration, RFC 8252 loopback, 90-day sliding window — a
// DIFFERENT app registration, out of scope here). Every place this module's
// Microsoft flow surfaces in the UI MUST say so; do not imply a 90-day
// session in browser mode (P3-D5, board row).
//
// GitHub has no equivalent SPA/public-client PKCE flow with CORS support —
// its token endpoint requires a confidential client. The browser path is
// therefore a fine-grained PAT paste-in (looksLikeFineGrainedPat/
// verifyGithubPat below), not a redirect flow.
//
// Every network/crypto primitive is an injected parameter (fetchImpl,
// cryptoImpl, storage) so the PKCE math, URL-building, and flow bookkeeping
// are unit-testable under plain node:test — same discipline as
// hub/oauth-pkce.mjs and ui/lib/handoff.mjs.

function base64url(bytes) {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function generatePkce(cryptoImpl = crypto) {
  const codeVerifier = base64url(cryptoImpl.getRandomValues(new Uint8Array(32)));
  const digest = await cryptoImpl.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const codeChallenge = base64url(new Uint8Array(digest));
  return { codeVerifier, codeChallenge };
}

export function randomState(cryptoImpl = crypto, byteLen = 16) {
  const bytes = cryptoImpl.getRandomValues(new Uint8Array(byteLen));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// --- Provider presets --------------------------------------------------

// SPA app registration (no client secret). The 24h refresh-token cap is a
// property of the "Single-page application" redirect-URI platform type
// itself, not a config knob — UI copy that surfaces this preset must be
// honest about daily reconnect (P3-D5).
export const MICROSOFT_SPA = {
  provider: "microsoft",
  authorizationEndpoint: (tenant = "common") => `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
  tokenEndpoint: (tenant = "common") => `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
  defaultScopes: ["offline_access", "Files.Read"],
  reconnectCopy:
    "Microsoft connections made in browser mode use a short-lived (about 24 hour) sign-in — you'll need to reconnect daily. Install the Helm engine for a 90-day connection instead.",
};

// drive.file + Picker ONLY (P3-D5 / P3-DEC-2, locked 2026-07-23). Both
// "drive.readonly" and the bare "drive" scope are Google RESTRICTED scopes
// that require an annual CASA security assessment ($500-4.5k/yr) — dead at
// a $0 budget. "drive.file" grants access only to files the user explicitly
// opens or creates through this app (via the Picker or a save dialog),
// which is exactly the access pattern Helm connectors need, and is NOT a
// restricted scope. Phase-1's H6 connector used drive.readonly — this WU
// migrates it too (see hub/connectors/google-drive-fetch.contract.json).
// scripts/lib/google-scope-lint.mjs gates every scope array in the repo
// against re-introducing drive.readonly/drive.
export const GOOGLE_DRIVE_FILE = {
  provider: "google",
  authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  tokenEndpoint: "https://oauth2.googleapis.com/token",
  defaultScopes: ["https://www.googleapis.com/auth/drive.file"],
};

export function buildAuthorizationUrl({ authorizationEndpoint, clientId, redirectUri, scopes, state, codeChallenge, extraParams = {} }) {
  if (!clientId) throw new Error("oauth-browser: clientId required");
  if (!redirectUri) throw new Error("oauth-browser: redirectUri required");
  const url = new URL(typeof authorizationEndpoint === "function" ? authorizationEndpoint() : authorizationEndpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  for (const [k, v] of Object.entries(extraParams)) url.searchParams.set(k, v);
  return url.toString();
}

const FLOW_KEY_PREFIX = "helm.oauth.flow.";

// Starts a browser OAuth flow: generates PKCE + state, persists the
// in-flight verifier/state/redirectUri/clientId in sessionStorage keyed by
// provider (an in-memory Map would not survive the full top-level
// navigation to the provider and back through /oauth-callback.html), and
// returns the URL the caller must navigate the TOP-LEVEL document to —
// never an iframe or popup (same P3-D3 reasoning as the daemon handoff:
// popups get eaten by blockers and can trip Cross-Origin-Opener-Policy).
export async function startBrowserFlow({ provider, authorizationEndpoint, clientId, redirectUri, scopes, extraParams, cryptoImpl = crypto, storage = sessionStorage }) {
  const { codeVerifier, codeChallenge } = await generatePkce(cryptoImpl);
  const state = randomState(cryptoImpl);
  storage.setItem(FLOW_KEY_PREFIX + provider, JSON.stringify({ codeVerifier, state, redirectUri, clientId }));
  const authorizationUrl = buildAuthorizationUrl({ authorizationEndpoint, clientId, redirectUri, scopes, state, codeChallenge, extraParams });
  return { authorizationUrl, state };
}

export function loadPendingFlow(provider, storage = sessionStorage) {
  const raw = storage.getItem(FLOW_KEY_PREFIX + provider);
  return raw ? JSON.parse(raw) : null;
}

export function clearPendingFlow(provider, storage = sessionStorage) {
  storage.removeItem(FLOW_KEY_PREFIX + provider);
}

// Completes the flow after /oauth-callback.html has relayed {code,state}
// into sessionStorage (see oauth-callback.mjs's consumeRelayedResult).
// Validates `state` itself — never trusts the callback page's own check
// alone; this is the function that actually spends the authorization code.
export async function completeBrowserFlow({ provider, code, state, tokenEndpoint, fetchImpl = fetch, storage = sessionStorage }) {
  const pending = loadPendingFlow(provider, storage);
  if (!pending) throw new Error(`oauth-browser: no pending ${provider} flow (expired, or a different tab/browser)`);
  if (state !== pending.state) {
    clearPendingFlow(provider, storage);
    throw new Error("oauth-browser: state mismatch");
  }

  const res = await fetchImpl(typeof tokenEndpoint === "function" ? tokenEndpoint() : tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: pending.redirectUri,
      client_id: pending.clientId,
      code_verifier: pending.codeVerifier,
    }),
  });
  clearPendingFlow(provider, storage);
  if (!res.ok) throw new Error(`oauth-browser: token exchange failed (${res.status})`);
  return res.json();
}

// --- GitHub: fine-grained PAT paste-in ---------------------------------

// Shape check only — not over-engineered format sniffing. Fine-grained PATs
// (github_pat_...) are GitHub's current recommendation over classic
// (ghp_...) tokens because they carry per-repo, per-permission scoping.
export function looksLikeFineGrainedPat(value) {
  return typeof value === "string" && /^github_pat_[A-Za-z0-9_]{20,}$/.test(value.trim());
}

// Confirms the pasted PAT actually authenticates, without ever logging it —
// callers should invoke this immediately before vaulting the token, never
// store the value on a failed result. Free to run live (no app registration
// needed); kept out of the offline blocking suite as a liveTest (see the
// paired .test.mjs) rather than skipped entirely.
export async function verifyGithubPat(pat, fetchImpl = fetch) {
  const res = await fetchImpl("https://api.github.com/user", {
    headers: { Authorization: `Bearer ${pat}`, Accept: "application/vnd.github+json" },
  });
  if (!res.ok) return { ok: false, status: res.status };
  const user = await res.json();
  return { ok: true, login: user.login };
}
