// Generic RFC 8252 loopback authorization-code + PKCE flow (D9, HELM-H5).
// Not tied to any real provider — tested here against an in-repo mock. The
// authorization redirect target is its OWN ephemeral single-shot listener,
// separate from the D8-hardened main API server: a top-level browser
// navigation back from the provider carries neither the pairing bearer token
// nor a same-origin Origin header, so it cannot pass through server.mjs's
// checks and must not be asked to. The ephemeral listener still binds
// 127.0.0.1-only, validates Host, and uses an unguessable per-flow path
// segment plus the OAuth `state` param as its own defense.
//
// Connection registry (connections.json) holds only non-secret metadata —
// provider, scopes, timestamps, and an opaque vault ref. Token values live
// exclusively in vault.mjs; this module never writes one to config, the
// registry file, or a log line (proven by vault-secret-gate.test.mjs).
import { createServer } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { vaultSet, vaultGet, vaultDelete } from "./vault.mjs";
import { log } from "./log.mjs";

const FLOW_TTL_MS = 5 * 60 * 1000; // RFC 8252 loopback flows are short-lived by nature
const FETCH_TIMEOUT_MS = 15 * 1000; // HELM-SEC-5 hardening: a hung provider endpoint must not stall the flow forever

// In-memory only — a flow is meaningless across a daemon restart (the
// ephemeral listener that could complete it is gone too).
const flows = new Map();

function base64url(buf) {
  return buf.toString("base64url");
}

// F4 (THREAT-MODEL §5): authorizationEndpoint/tokenEndpoint must be https —
// an http: tokenEndpoint sends the auth code + PKCE code_verifier in
// cleartext. Loopback is exempt (127.0.0.1 mock provider used by tests).
export function isSecureEndpoint(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return false;
  }
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && url.hostname === "127.0.0.1";
}

export function generatePkce() {
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(createHash("sha256").update(codeVerifier).digest());
  return { codeVerifier, codeChallenge };
}

function connectionsPath() {
  return statePath("connections.json");
}

function loadConnections() {
  const p = connectionsPath();
  if (!existsSync(p)) return [];
  return JSON.parse(readFileSync(p, "utf8"));
}

function saveConnections(list) {
  writeFileSync(connectionsPath(), JSON.stringify(list, null, 2) + "\n", { mode: 0o600 });
}

// Safe view: exactly what the UI's Connect view needs to show pre-/post-consent,
// never the vault ref's contents.
function publicView(conn) {
  const { vaultRef: _vaultRef, ...safe } = conn;
  return { ...safe, status: connectionStatus(conn) };
}

function connectionStatus(conn) {
  if (conn.status === "revoked") return "revoked";
  if (conn.expiresAt && Date.now() > conn.expiresAt) return "expired";
  return "active";
}

function closeListener(flow) {
  if (flow.server) {
    try {
      flow.server.close();
    } catch {
      // already closed
    }
  }
  if (flow.timeout) clearTimeout(flow.timeout);
}

async function exchangeCode({ tokenEndpoint, code, codeVerifier, redirectUri, clientId }) {
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: codeVerifier,
    }),
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);
  return res.json();
}

function completeFlow(flow, tokens) {
  const connectionId = randomBytes(8).toString("hex");
  const vaultRef = `helm/oauth/${connectionId}`;
  vaultSet(vaultRef, {
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token ?? null,
    token_type: tokens.token_type ?? "Bearer",
  });
  const conn = {
    id: connectionId,
    provider: flow.provider,
    scopes: flow.scopes,
    clientId: flow.clientId,
    tokenEndpoint: flow.tokenEndpoint,
    revocationEndpoint: flow.revocationEndpoint ?? null,
    grantedAt: Date.now(),
    expiresAt: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : null,
    status: "active",
    vaultRef,
  };
  const list = loadConnections();
  list.push(conn);
  saveConnections(list);
  flow.status = "complete";
  flow.connectionId = connectionId;
  log.info("oauth flow completed", { provider: flow.provider, connectionId, scopes: flow.scopes });
}

function handleCallback(flow, req, res, port) {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const html = (msg) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<!doctype html><title>Helm</title><body>${msg} You can close this window.</body>`);
  };

  if (req.headers.host !== `127.0.0.1:${port}`) {
    res.writeHead(403);
    return res.end();
  }
  if (url.pathname !== flow.callbackPath) {
    res.writeHead(404);
    return res.end();
  }

  const err = url.searchParams.get("error");
  const state = url.searchParams.get("state");
  const code = url.searchParams.get("code");

  if (err) {
    flow.status = "error";
    flow.error = err;
    closeListener(flow);
    return html(`Authorization failed: ${err}.`);
  }
  if (state !== flow.state) {
    flow.status = "error";
    flow.error = "state_mismatch";
    closeListener(flow);
    return html("Authorization failed: state mismatch.");
  }
  if (!code) {
    flow.status = "error";
    flow.error = "missing_code";
    closeListener(flow);
    return html("Authorization failed: no code returned.");
  }

  html("Authorization received, finishing sign-in…");
  closeListener(flow);

  exchangeCode({
    tokenEndpoint: flow.tokenEndpoint,
    code,
    codeVerifier: flow.codeVerifier,
    redirectUri: flow.redirectUri,
    clientId: flow.clientId,
  })
    .then((tokens) => completeFlow(flow, tokens))
    .catch((error) => {
      flow.status = "error";
      flow.error = String(error.message ?? error);
      log.error("oauth token exchange failed", { provider: flow.provider, error: flow.error });
    });
}

// Starts a flow: opens the one-shot loopback callback listener, builds the
// authorization URL, and returns immediately. The caller (UI, via the daemon
// API) opens authorizationUrl in the system browser and polls getFlowStatus.
export async function startFlow({ provider, authorizationEndpoint, tokenEndpoint, revocationEndpoint, clientId, scopes }) {
  const { codeVerifier, codeChallenge } = generatePkce();
  const state = randomBytes(16).toString("hex");
  const pathToken = randomBytes(8).toString("hex");
  const flowId = randomBytes(16).toString("hex");

  const flow = {
    id: flowId,
    provider,
    tokenEndpoint,
    revocationEndpoint,
    clientId,
    scopes,
    codeVerifier,
    state,
    callbackPath: `/callback/${pathToken}`,
    status: "pending",
    server: null,
    redirectUri: null,
  };

  await new Promise((resolve, reject) => {
    const server = createServer((req, res) => handleCallback(flow, req, res, server.address().port));
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      flow.server = server;
      flow.redirectUri = `http://127.0.0.1:${server.address().port}${flow.callbackPath}`;
      resolve();
    });
  });

  flow.timeout = setTimeout(() => {
    if (flow.status === "pending") {
      flow.status = "expired";
      closeListener(flow);
    }
  }, FLOW_TTL_MS);

  flows.set(flowId, flow);

  const authUrl = new URL(authorizationEndpoint);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", flow.redirectUri);
  authUrl.searchParams.set("scope", scopes.join(" "));
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return { flowId, authorizationUrl: authUrl.toString(), scopes };
}

export function getFlowStatus(flowId) {
  const flow = flows.get(flowId);
  if (!flow) return null;
  return { flowId, status: flow.status, connectionId: flow.connectionId ?? null, error: flow.error ?? null };
}

export function listConnections() {
  return loadConnections().map(publicView);
}

export async function revokeConnection(connectionId) {
  const list = loadConnections();
  const conn = list.find((c) => c.id === connectionId);
  if (!conn) return null;

  if (conn.revocationEndpoint) {
    const tokens = vaultGet(conn.vaultRef);
    if (tokens?.access_token) {
      try {
        await fetch(conn.revocationEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: tokens.access_token, client_id: conn.clientId }),
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
      } catch (error) {
        log.warn("provider revocation call failed (still revoking locally)", { connectionId, error: String(error) });
      }
    }
  }

  vaultDelete(conn.vaultRef);
  conn.status = "revoked";
  conn.revokedAt = Date.now();
  saveConnections(list);
  log.info("oauth connection revoked", { connectionId, provider: conn.provider });
  return publicView(conn);
}
