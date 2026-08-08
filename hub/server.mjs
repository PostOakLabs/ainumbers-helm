// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Loopback REST + SSE server. D8 hardening, in order, on every request:
//   1. Host header must exactly equal 127.0.0.1:<port>        (DNS-rebinding defense)
//   2. Origin header must exactly equal the configured origin  (no wildcard CORS)
//   3. Authorization: Bearer <token> must match                (pairing token)
// GET handlers are read-only by construction — no side effects on GET.
import { createServer } from "node:http";
import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tokenMatches, redeemPairingNonce, createStreamTicket, redeemStreamTicket, createExportTicket, pairingUrl, createPairingNonce, createSignerConfigTicket, redeemSignerConfigTicket } from "./token.mjs";
import { loadSignerConfig, writeSignerConfig } from "./signer-config.mjs";
import { signChallenge, fingerprintPublicKeyDer } from "./challenge.mjs";
import { log } from "./log.mjs";
import { startFlow, getFlowStatus, listConnections, revokeConnection, isSecureEndpoint } from "./oauth-pkce.mjs";
import { serveStatic } from "./static.mjs";
import { listPacks, getPack } from "./packs.mjs";
import { listTemplates, getTemplate, buildTemplateManifest } from "./templates.mjs";
import { executeRun, manifestDigest } from "./run.mjs";
import { createKernelStepRunner } from "./kernel-runner.mjs";
import { publishRunEvent, subscribeRunEvents } from "./event-bus.mjs";
import { startWorkflowRun, getRunsInFlightCount as getActionsRunsInFlightCount } from "./run-actions.mjs";
import { createConnectorStepDispatcher } from "./connectors/dispatch.mjs";
import { handleMcp, handleMcpMethodNotAllowed } from "./mcp.mjs";
import { haGateCheckFor, findHeldGate, recordReplay, submitHaRecord } from "./ha-gate.mjs";
import { provenanceStatus } from "./state-snapshot.mjs";
import { recordsForSubject, getSlot } from "./ha-store.mjs";
import { createMatter, getMatter, listMatters, updateMatter, deleteMatter, closeMatter, getMatterExport } from "./matter-store.mjs";
import { buildKernelCard, buildEucEntry } from "./euc-register.mjs";
import { renderKernelCardHtml, renderEucEntryHtml } from "../ui/lib/euc-html.mjs";
import { renderKernelDecisionTableHtml, buildKernelDecisionTableDmn } from "../ui/lib/decision-table.mjs";
import { importMigrationBundle } from "./migration-import.mjs";
import { buildWorkflowExport, parseWorkflowExport } from "./workflow-export.mjs";
import { exportBpmn } from "./bpmn-export.mjs";
import { checkVersion, DEFAULT_VERSION_CHECK_URL } from "./version-check.mjs";
import { DEFAULT_IDLE_TIMEOUT_MS } from "./idle-timer.mjs";
import { loadContract, recordEgress } from "./connector.mjs";
import { createInboundWebhookConnector, CONNECTOR_ID as INBOUND_WEBHOOK_CONNECTOR_ID } from "./connectors/inbound-webhook.mjs";
import { vaultGet } from "./vault.mjs";
import { autostartStatus, installAutostart, uninstallAutostart } from "./autostart.mjs";
import { installShortcut, uninstallShortcut, isShortcutInstalled, shortcutLocation } from "./shortcut.mjs";
import {
  verifyWebhookSignature,
  isTimestampFresh,
  checkAndConsumeNonce,
  getIdempotentResponse,
  storeIdempotentResponse,
} from "./webhook-guard.mjs";

const START = Date.now();
const HERE = dirname(fileURLToPath(import.meta.url));
export const DAEMON_VERSION = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8")).version;
// UI↔daemon protocol versions this build understands (P3-D6). A hosted UI
// intersects its own list against this one to decide compatible / degraded.
export const SUPPORTED_API_VERSIONS = ["helm/1"];

// P3-D3: the hosted marketing origin is allowed to hit ONLY the two
// detection-surface routes below, cross-origin, pre-auth — never anything
// that touches vault/journal/run data. Exact match, never a wildcard.
const DETECTION_ORIGIN = "https://ainumbers.co";
const DETECTION_PATHS = new Set(["/version", "/pair/challenge"]);

// HELM-INBOUND-WEBHOOK-1: the "governed step" push path an external
// orchestrator (n8n/Zapier/Make, or a bank's PA flow — HELM-PHASE3-BUILD-SPEC
// §item 6 — running on this SAME machine, since helmd never opens its socket
// beyond 127.0.0.1) uses to hand a step completion in. Pre-auth like the
// DETECTION_PATHS above, but for a different reason: the caller has neither
// the browser's Origin nor the daemon's pairing bearer token — its own
// authentication is the HMAC-over-raw-body check inside the handler, which
// MUST run before ANY body parsing or allowlist check.
const INBOUND_WEBHOOK_PATH = "/connectors/inbound-webhook";
const DEFAULT_INBOUND_WEBHOOK_CONTRACT_PATH = join(HERE, "connectors", "inbound-webhook.contract.json");

function checkHost(req, port) {
  return req.headers.host === `127.0.0.1:${port}`;
}

// req.url must NEVER reach a log line: the bearer token rides in the query
// string on /events (EventSource can't set an Authorization header, see the
// exception below), so logging a rejected request verbatim writes a WORKING
// credential to stdout — which the macOS LaunchAgent can capture to a file.
// Log the path only. Falls back to a placeholder rather than throwing, since
// this runs on the reject path where req.url may be malformed.
function logPath(req) {
  try {
    return new URL(req.url, "http://x").pathname;
  } catch {
    return "<unparsable>";
  }
}

// HELM-ORIGIN-1: browsers omit the Origin header on same-origin GET/HEAD
// requests (fetch spec — Origin is only appended for CORS requests, POST/
// other unsafe methods, and navigations) while always including it on POST,
// which is why the loopback UI's own GETs (/health, /events, /version-check,
// ...) were rejected while its POSTs succeeded. Referer can't stand in for
// it either: static.mjs serves the UI shell with Referrer-Policy:
// no-referrer, so Referer is absent on the exact same requests. Sec-Fetch-Site
// is the fix — every modern browser sets it unconditionally, it is a
// forbidden header name a page's own JS cannot set or override (same
// guarantee Origin itself relies on), and it is untouched by
// Referrer-Policy. Fall back to it ONLY when Origin is genuinely absent —
// a present-but-wrong Origin is never forgiven by this fallback.
function isSameOriginFallback(req) {
  return req.headers.origin === undefined && req.headers["sec-fetch-site"] === "same-origin";
}

function checkOrigin(req, allowedOrigin) {
  return req.headers.origin === allowedOrigin || isSameOriginFallback(req);
}

function applyCors(res, allowedOrigin) {
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Vary", "Origin");
  // MCP-Protocol-Version/Mcp-Method/Mcp-Name (SEP-2243, HELM-H9's /mcp) ride
  // alongside the pre-existing Authorization/Content-Type set.
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
}

function deny(res, status, error) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error }));
}

function sendJson(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function sendHtml(res, status, html) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendXml(res, status, xml) {
  res.writeHead(status, { "Content-Type": "application/xml; charset=utf-8" });
  res.end(xml);
}

// Raw bytes, not the parsed-JSON readJsonBody above — the HMAC signature
// covers the EXACT bytes the caller sent, and verifying it must happen
// before JSON.parse ever runs (a parse that mutates whitespace/key order
// would make a byte-based signature unverifiable after the fact).
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

// §18.4: the idle timeout must be announced, not merely enforced — this is
// the one route every client (Operate, the CLI's implicit health probes)
// already polls, so it's where "Helm stops when idle" gets said out loud.
function handleHealth(req, res, params, db, idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok", uptimeMs: Date.now() - START, version: DAEMON_VERSION, idleTimeoutMs }));
}

// GET /version-check (HELM-P4-J4): authenticated wrapper around the same
// passive notice `helmd doctor` already surfaces (version-check.mjs, D10) —
// the paired UI polls this to power the skew banner's "download new
// installer" prompt. Same non-blocking contract: unreachable/disabled never
// errors, it just reports checked:false.
async function handleVersionCheck(req, res, versionCheckUrl) {
  if (!versionCheckUrl) return sendJson(res, 200, { checked: false, reason: "disabled" });
  const result = await checkVersion({ currentVersion: DAEMON_VERSION, url: versionCheckUrl });
  sendJson(res, 200, result);
}

// POST /vault/connections/begin — starts an OAuth PKCE loopback flow (D9,
// HELM-H5). Side-effecting, hence POST despite this being the only vault
// write reachable from this router today.
async function handleBeginConnection(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  for (const field of ["provider", "authorizationEndpoint", "tokenEndpoint", "clientId", "scopes"]) {
    if (!body[field]) return deny(res, 400, `missing_${field}`);
  }
  if (!isSecureEndpoint(body.authorizationEndpoint) || !isSecureEndpoint(body.tokenEndpoint)) {
    return deny(res, 400, "insecure_endpoint");
  }
  try {
    const flow = await startFlow(body);
    sendJson(res, 200, flow);
  } catch (err) {
    log.error("oauth begin failed", { error: String(err) });
    deny(res, 500, "flow_start_failed");
  }
}

function handleListConnections(req, res) {
  sendJson(res, 200, { connections: listConnections() });
}

// HELM-BIND-3 §4.2: ui/views/connect.mjs's "Daemon connectors" section fetches
// "/connectors" — a route that never existed (only POST /connectors/inbound-
// webhook did), so the tab could not succeed against any shipped daemon.
// Measured directly (unmodified origin/main daemon, real HTTP request): GET
// /connectors returned a bare 404 {"error":"not_found"}, no cached prior
// response, so fetchWithFallback's state was "unavailable" -> classifyBlockedState
// returned "too-old" -> the tab rendered "helmd answered, but the connector
// catalog isn't served by this version of Helm yet." for every visitor,
// forever. Measured after this route exists: GET /connectors returns 200
// with the catalog below, so the tab renders real cards instead. This lists
// the connector contracts bundled with this daemon build (the ones
// connectors/*.mjs can actually execute) — status is deliberately static
// "not connected": none of these local allowlist contracts corresponds to an
// oauth-pkce.mjs provider key (listConnections() tracks browser-OAuth
// connections, a different set), so there is no live status to report yet.
function connectorCatalogEntries(inboundWebhookContractPath) {
  const paths = [
    join(HERE, "connectors", "http-send.contract.json"),
    join(HERE, "connectors", "google-drive-fetch.contract.json"),
    join(HERE, "connectors", "smtp-send.contract.json"),
    inboundWebhookContractPath,
  ];
  return paths.map((p) => ({ contract: loadContract(p).contract, status: "not connected" }));
}

function handleListConnectors(req, res, params, reqDb, inboundWebhookContractPath) {
  sendJson(res, 200, { connectors: connectorCatalogEntries(inboundWebhookContractPath) });
}

// POST /pair/redeem {nonce} — records that a given pairing LINK was
// consumed (P3-D9 single-use). Requires the durable bearer token like any
// other route (the nonce alone unlocks nothing); a failed redeem is
// non-fatal to the caller's session (it already holds the durable token)
// but signals a replayed/expired link for anything that wants to react.
async function handlePairRedeem(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  if (!body.nonce) return deny(res, 400, "missing_nonce");
  if (!redeemPairingNonce(body.nonce)) return deny(res, 401, "pairing_expired_or_used");
  sendJson(res, 200, { ok: true });
}

// POST /pair/relink (HELM-REPAIR-LINK-1): mints a fresh #token= pairing URL
// for a browser that is ALREADY paired but about to lose (or has no other
// route back to) its sessionStorage token — the diagnosed dead end in
// HELM-PAIR-DIAG-1 (closed tab / browser restart / no in-app re-pair link,
// and 2026.8.4 stopped auto-opening a tab on ordinary restarts). Requires
// the SAME Host+Origin+Bearer gate as every other mutating route below —
// there is no separate check here, and there must not be one: this mints a
// working credential, so an unauthenticated path to it would be a full auth
// bypass. The durable bearer token itself is NEVER rotated (pairingUrl
// reuses the caller's own `token`, same as every boot-time mint in
// index.mjs) — only the pairing NONCE is fresh, single-use, and
// short-TTL via createPairingNonce/redeemPairingNonce (P3-D9), matching the
// existing pairing-link discipline exactly. Rotating the durable token would
// invalidate any other tab's live EventSource/health polling mid-connection
// (token.mjs's own reasoning for why the nonce, not the token, is what's
// disposable). The response body is JSON, never a redirect or a query
// string on this route's own URL, and callers (operate.mjs) must never
// console.log or otherwise persist it outside the clipboard.
function handlePairRelink(req, res, params, db, port, token, identityKeys) {
  const fingerprint = identityKeys
    ? fingerprintPublicKeyDer(identityKeys.ed25519.publicKey.export({ format: "der", type: "spki" }).toString("base64"))
    : undefined;
  sendJson(res, 200, { url: pairingUrl(token, port, createPairingNonce(), fingerprint) });
}

function checkDetectionOrigin(req, allowedOrigin) {
  const origin = req.headers.origin;
  return origin === allowedOrigin || origin === DETECTION_ORIGIN || isSameOriginFallback(req);
}

// GET /version + GET /pair/challenge: reachable cross-origin from the
// hosted ainumbers.co page (Chrome/Firefox LNA-gated detection enhancement,
// P3-D3) with NO bearer token — that's deliberate, they carry nothing
// sensitive (a version string; a nonce signed by the daemon's own identity
// key). Host check still applies (done by the caller before this runs).
function handleDetectionRoute(req, res, pathname, identityKeys, allowedOrigin) {
  if (!checkDetectionOrigin(req, allowedOrigin)) {
    log.warn("rejected: detection-route origin mismatch", { origin: req.headers.origin, path: pathname });
    return deny(res, 403, "origin_mismatch");
  }
  // A same-origin fallback request (isSameOriginFallback) has no Origin
  // header to echo — fall back to allowedOrigin, since that's what the
  // request actually matched against in checkDetectionOrigin above.
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || allowedOrigin);
  res.setHeader("Vary", "Origin");
  if (pathname === "/version") {
    return sendJson(res, 200, { daemon: DAEMON_VERSION, api: SUPPORTED_API_VERSIONS });
  }
  // /pair/challenge
  if (!identityKeys) return deny(res, 503, "identity_unavailable");
  return sendJson(res, 200, signChallenge(identityKeys.ed25519));
}

// Private Network Access preflight: Chrome sends this OPTIONS before the
// real cross-origin GET whenever the client fetch used
// targetAddressSpace:'loopback'. Answering it is what makes the detection
// probe (P3-D3) work at all in a Chrome-managed profile with LNA enabled.
function handleDetectionPreflight(req, res, allowedOrigin) {
  if (!checkDetectionOrigin(req, allowedOrigin)) return deny(res, 403, "origin_mismatch");
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || allowedOrigin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Private-Network", "true");
  res.writeHead(204);
  res.end();
}

function handleFlowStatus(req, res, params) {
  const status = getFlowStatus(params.flowId);
  if (!status) return deny(res, 404, "flow_not_found");
  sendJson(res, 200, status);
}

async function handleRevoke(req, res, params) {
  try {
    const result = await revokeConnection(params.id);
    if (!result) return deny(res, 404, "connection_not_found");
    sendJson(res, 200, result);
  } catch (err) {
    log.error("revoke failed", { error: String(err) });
    deny(res, 500, "revoke_failed");
  }
}

export const MAX_SSE_CONNECTIONS = 20; // HELM-SEC-5 hardening: unbounded /events connections could exhaust local handles
let sseConnections = 0;
// §18.2 idle-shutdown suppression signal: true for the wall-clock duration of
// an in-flight run (handleRunStart's fire-and-forget chain and
// handleRunResume's awaited one both bump this), not merely while a client
// is watching its /events stream.
let runsInFlight = 0; // handleRunResume only — startWorkflowRun tracks its own in run-actions.mjs
export function getSseConnectionCount() {
  return sseConnections;
}
export function getRunsInFlightCount() {
  return runsInFlight + getActionsRunsInFlightCount();
}

// POST /events/ticket (HELM-UX-1 §7.4): authenticated the normal way (bearer
// header, already past the router's tokenMatches gate by the time this
// runs) — mints a ticket /events can redeem in its query string instead of
// the durable bearer token, so the credential never sits in a URL for the
// life of a session.
function handleEventsTicket(req, res) {
  sendJson(res, 200, { ticket: createStreamTicket() });
}

// POST /evidence/export/ticket (HELM-H9): mints the short-lived, single-use
// ticket the MCP evidence.export tool requires (token.mjs createExportTicket
// doc comment). This route itself rides the ordinary bearer gate like any
// other — the separation that matters is that the paired UI is meant to call
// this ONLY after showing the user a consent prompt, and an MCP tools/call
// has no way to reach this route at all (it isn't an MCP tool).
function handleEvidenceExportTicket(req, res) {
  sendJson(res, 200, { ticket: createExportTicket() });
}

// GET /signer/config (SIGN-SEAM-1 / SIGNING-SURFACES-BUILD-SPEC.md §3):
// read-only, no side effects — returns the current external-signer config
// (or null if unset) for the paired UI to render. Everything in it is
// non-secret (see signer-config.mjs header), so no ticket is needed to read
// it — only to CHANGE it (below).
function handleSignerConfigGet(req, res) {
  sendJson(res, 200, { config: loadSignerConfig() });
}

// POST /signer/config/ticket: mints the short-lived, single-use consent
// ticket phil condition #5 requires before the signer command can be
// repointed — the signer command IS key access, so this is consent-gated at
// the same tier as pairing/token changes (createExportTicket above is the
// precedent this copies). Not registered as an MCP tool (see ROUTES / the
// MCP tool list in mcp.mjs) and never reachable from an MCP tools/call — an
// agent holding only the bearer token cannot mint one; only the paired
// browser UI is meant to call this, and only after it has shown the user
// what is about to change.
function handleSignerConfigTicket(req, res) {
  sendJson(res, 200, { ticket: createSignerConfigTicket() });
}

// POST /signer/config {ticket, config}: the actual write. Requires a ticket
// minted by the route above — a POST with no ticket, an expired ticket, or
// a reused (already-redeemed) ticket is refused with 403 consent_required
// before validateSignerConfig ever runs, so a bearer-token-only caller (an
// agent, a compromised page that got past Origin somehow) cannot repoint the
// signer even if it can reach this route at all.
async function handleSignerConfigUpdate(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  if (typeof body.ticket !== "string" || !redeemSignerConfigTicket(body.ticket)) {
    return deny(res, 403, "consent_required");
  }
  try {
    const config = writeSignerConfig(body.config);
    sendJson(res, 200, { config });
  } catch (err) {
    deny(res, 400, "invalid_signer_config");
  }
}

// POST /shutdown (HELM-UX-1 §8, Operate view Quit button).
//
// §2 (shipped) says never add an HTTP shutdown route, reasoning that the CLI
// channel's OS-level pipe/socket ACL is the right trust boundary for
// stopping helmd and that an HTTP route "would be reachable by any local
// process." §8 (this WU) asks for a browser Quit button, and a browser has
// no channel to the CLI's named pipe / UDS at all — POSTing here, through
// the SAME Host+Origin+Bearer gate every other mutating route already goes
// through (identical exposure to /backup, /run/start, /run/resume), is the
// only way a page can drive it. This route is gated no more loosely than
// those already-shipped routes; flagged in the PR for a second look against
// §2's literal wording rather than silently resolved either way.
//
// Must reply before exiting (§2, same discipline as the CLI `stop` verb) —
// a daemon that exits first gives the browser a network error and the UI
// reports failure for what was actually a successful stop.
function handleShutdown(req, res, params, db, exitFn) {
  sendJson(res, 200, { stopping: true, pid: process.pid });
  setTimeout(() => exitFn(), 50);
}

// --- HELM-AUTOSTART-1: consent-gated autostart ---
//
// Autostart used to be installed by helmd itself on first run, with no user
// action of any kind (index.mjs, removed). These two routes are what replaces
// it: the pairing tab reads GET /autostart to render a toggle that reflects
// what is ACTUALLY on the machine, and POSTs here when the user ticks it.
//
// POST, never GET, for the write half. A GET that installs persistence is
// reachable from `<img src="http://127.0.0.1:4173/autostart?on=1">` or a
// prefetch — paths where a page's script never runs and so the Origin gate is
// the only thing standing in the way. Keeping the write on POST means the
// "no side effects on GET" invariant at the top of this file still holds, and
// there is no single-URL form of the attack at all.
//
// Both routes go through the ordinary Host + Origin + Bearer gate below —
// they are in ROUTES, NOT in serveStatic's pre-auth allowlist and NOT in
// DETECTION_PATHS (which has a wider origin allowance and no token at all).
// server.test.mjs asserts that directly rather than trusting registration.
const DEFAULT_AUTOSTART_OPS = {
  status: autostartStatus,
  install: installAutostart,
  uninstall: uninstallAutostart,
  shortcutStatus: () => ({ installed: isShortcutInstalled(), location: shortcutLocation() }),
  installShortcut,
  uninstallShortcut,
};

function autostartPayload(ops) {
  const status = ops.status();
  const shortcut = ops.shortcutStatus();
  return {
    autostart: {
      supported: status.supported,
      installed: status.installed,
      stale: status.stale,
      reason: status.reason,
      location: status.location,
      recorded: status.recorded,
    },
    shortcut: {
      supported: shortcut.location !== null,
      installed: shortcut.installed,
      location: shortcut.location,
    },
  };
}

function handleAutostartStatus(req, res, params, db, ops = DEFAULT_AUTOSTART_OPS) {
  sendJson(res, 200, autostartPayload(ops));
}

async function handleAutostartSet(req, res, params, db, ops = DEFAULT_AUTOSTART_OPS) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  const wantAutostart = typeof body.autostart === "boolean";
  const wantShortcut = typeof body.shortcut === "boolean";
  if (!wantAutostart && !wantShortcut) return deny(res, 400, "missing_autostart_or_shortcut");

  // reg.exe / launchctl / the WScript.Shell PowerShell call can all fail on a
  // locked-down machine. Report it as a failure rather than letting it 500 as
  // an unhandled rejection — the UI needs to put the toggle back where it was.
  try {
    if (wantAutostart) {
      if (body.autostart) ops.install();
      else ops.uninstall();
    }
    if (wantShortcut) {
      if (body.shortcut) ops.installShortcut();
      else ops.uninstallShortcut();
    }
  } catch (err) {
    log.warn("autostart change failed", { error: String(err?.message || err) });
    return sendJson(res, 500, { error: "autostart_failed", detail: String(err?.message || err), ...autostartPayload(ops) });
  }
  // Echo the re-read state, never the requested state: on an unsupported
  // platform install() returns {supported:false} and nothing was written, and
  // a UI that trusted its own request would show a toggle that lies.
  sendJson(res, 200, autostartPayload(ops));
}

// run_id-scoped progress: an EventSource with no ?run_id just gets ready +
// heartbeats, same as before this WU (used by Connect/Operate today).
function handleEvents(req, res) {
  if (sseConnections >= MAX_SSE_CONNECTIONS) {
    res.writeHead(503, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "too_many_connections" }));
  }
  sseConnections++;
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.write(`event: ready\ndata: {}\n\n`);
  const heartbeat = setInterval(() => res.write(`event: heartbeat\ndata: {}\n\n`), 15000);
  const runId = new URL(req.url, "http://x").searchParams.get("run_id");
  const unsubscribe = runId
    ? subscribeRunEvents(runId, (data) => res.write(`event: progress\ndata: ${JSON.stringify(data)}\n\n`))
    : () => {};
  req.on("close", () => {
    clearInterval(heartbeat);
    unsubscribe();
    sseConnections--;
  });
}

// GET /workflows — Choose's catalog (P2-C1's compiled packs, listPacks()).
function handleWorkflows(req, res) {
  sendJson(res, 200, { workflows: listPacks() });
}

// GET /templates — Choose's Templates rail (HELM-P3-G10): curated
// compliance-scenario templates over the compiled catalog.
function handleTemplates(req, res) {
  sendJson(res, 200, { templates: listTemplates() });
}

// GET /templates/:slug — template detail incl. a manifest pre-wired with
// sample policy_parameters, ready for one-click Run.
function handleTemplateDetail(req, res, params) {
  const template = getTemplate(params.slug);
  if (!template) return deny(res, 404, "template_not_found");
  const manifest = buildTemplateManifest(template);
  if (!manifest) return deny(res, 404, "workflow_not_found");
  const pack = getPack(template.workflow_id);
  sendJson(res, 200, { ...template, name: pack?.name, outcome: pack?.outcome, manifest });
}

// GET /workflow-manifest?workflow_id=... — Canvas's DAG source. Returns the
// pack's manifest field, not the pack wrapper — matches the shape
// buildDag()/manifestDigest() and the run engine's executeRun() all expect.
function handleWorkflowManifest(req, res) {
  const workflowId = new URL(req.url, "http://x").searchParams.get("workflow_id");
  if (!workflowId) return deny(res, 400, "missing_workflow_id");
  const pack = getPack(workflowId);
  if (!pack) return deny(res, 404, "workflow_not_found");
  sendJson(res, 200, pack.manifest);
}

// POST /run/start {workflow_id, dry_run, inputs?} — kicks off the H4 run engine
// (run.mjs executeRun) against a compiled pack. Responds with the run_id
// immediately (fire-and-forget) so the caller can open the /events?run_id=
// SSE stream before the run finishes — that's what makes progress "live"
// rather than a summary the client requests after the fact.
async function handleRunStart(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  let result;
  try {
    result = startWorkflowRun(db, {
      workflowId: body.workflow_id, templateSlug: body.template_slug, dryRun: !!body.dry_run,
      // HELM-BIND-0: optional, keyed by node_id -> policy_parameters. Not
      // reachable via POST /mcp — mcp.mjs's workflow.run/dry_run tool
      // schemas declare only workflow_id/template_slug and destructure args
      // explicitly, so an MCP client cannot supply this field.
      inputs: body.inputs,
      // HELM-BIND-WIRE-1 §4.3: this REST route is the human/UI path — the
      // ONLY call site allowed to enable connector/action dispatch. mcp.mjs's
      // call to the same startWorkflowRun never sets this, so an MCP
      // tools/call gets callerOrigin undefined and dispatch stays off.
      callerOrigin: "ui",
    });
  } catch (err) {
    if (err && err.status) return deny(res, err.status, err.error);
    throw err;
  }
  sendJson(res, 200, result);
}

// POST /run/resume {run_id} — re-invokes executeRun for a run currently
// `awaiting_data` on a §27.4 gate hold (HELM-HA-1). Same idempotent-resume
// path crash-recovery already uses (run.mjs's executeRun re-checks every
// unmemoized step from scratch) — this route is just "call it again now"
// instead of waiting for the next daemon restart. A run that isn't actually
// held (unknown id, wrong state) is a 404/409, never silently a no-op 200.
async function handleRunResume(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  if (!body.run_id) return deny(res, 400, "missing_run_id");
  const row = db.prepare("SELECT * FROM runs WHERE run_id = ?").get(body.run_id);
  if (!row) return deny(res, 404, "run_not_found");
  if (row.state !== "awaiting_data") return deny(res, 409, "run_not_held");

  const manifest = JSON.parse(row.manifest_json);
  const runId = body.run_id;
  // HELM-BIND-WIRE-1 §4.1: /run/resume is REST-only — mcp.mjs has no
  // resume tool at all (grep confirms no "resume" case in its tools/call
  // switch), so this call site can never be reached via POST /mcp and needs
  // no origin gate: unlike startWorkflowRun, there is no ambiguous caller
  // here to fail closed against.
  const workflowManifestDigest = manifestDigest(manifest);
  const kernelStepRunner = createKernelStepRunner({ otherKindsRunner: createConnectorStepDispatcher({ db, workflowManifestDigest }) });
  const stepRunner = async (step, ctx) => {
    const output = await kernelStepRunner(step, ctx);
    publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
    return output;
  };
  // HELM-BIND-WIRE-1: canDispatch parity, same reasoning as run-actions.mjs's
  // startWorkflowRun — the wrapper stepRunner passed to executeRun must
  // carry kernelStepRunner's canDispatch or dry-run silently stops checking it.
  stepRunner.canDispatch = kernelStepRunner.canDispatch;

  runsInFlight++;
  try {
    const result = await executeRun(db, { runId, manifest, dryRun: !!row.dry_run, stepRunner, gateCheck: haGateCheckFor(db) });
    publishRunEvent(runId, { run_id: runId, state: result.state, execution_hash: result.executionHash, held: result.held ?? null });
    sendJson(res, 200, { run_id: runId, state: result.state, held: result.held ?? null });
  } catch (err) {
    log.error("run engine: resume failed", { runId, error: String(err?.message || err) });
    publishRunEvent(runId, { run_id: runId, state: "failed", error: String(err?.message || err) });
    deny(res, 500, "resume_failed");
  } finally {
    runsInFlight--;
  }
}

function digestOf(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

// POST /connectors/inbound-webhook (HELM-INBOUND-WEBHOOK-1): the n8n/Zapier/PA
// "governed step" push path. Pre-auth (see INBOUND_WEBHOOK_PATH above) — this
// handler is its OWN authentication+replay+idempotency gate, in a fixed
// order matching phil's four preconditions (research/PERSONA-phil-2026-07-26.md
// Option 4):
//   1. HMAC-over-raw-body BEFORE assertEgressAllowed (never after, never
//      instead of).
//   2. timestamp+nonce replay check, distinct from the connector's own
//      content-digest journal.
//   3. idempotency-key dedup BEFORE the workflow step (the connector call /
//      run-resume) ever executes — a legitimate retry short-circuits to the
//      cached response instead of re-running anything.
//   4. deny-by-default run-resume: only a contract whose `scopes` explicitly
//      lists "run.resume" may resume a paused run at all, and even then
//      run.mjs's own gateCheck re-verifies the §27.4 hold — this route never
//      constructs or forwards an HA approval on the caller's behalf, so an
//      unsatisfied human-review gate cannot be completed through here no
//      matter what the contract grants.
async function handleInboundWebhook(req, res, db, contract, contractDigest) {
  if (!db) return deny(res, 503, "engine_unavailable");

  let raw;
  try {
    raw = await readRawBody(req);
  } catch {
    return deny(res, 400, "invalid_body");
  }

  const secretRef = contract.vault_scope?.[0];
  const secretRaw = secretRef ? vaultGet(secretRef) : null;
  const secret = typeof secretRaw === "string" ? secretRaw : secretRaw?.value;
  if (!secret) {
    log.error("inbound-webhook: no signing secret configured", { ref: secretRef });
    return deny(res, 503, "webhook_not_configured");
  }

  // (1) HMAC-over-raw-body — verified BEFORE assertEgressAllowed runs (that
  // happens inside connector.send() below) and journalled as a DIFFERENT
  // signal ("auth_failed") from an allowlist "blocked", per phil's explicit
  // instruction not to collapse the two.
  const signatureHeader = req.headers["x-helm-webhook-signature"];
  if (!verifyWebhookSignature(secret, raw, signatureHeader)) {
    recordEgress(db, {
      connectorId: INBOUND_WEBHOOK_CONNECTOR_ID,
      destinationHost: req.socket.remoteAddress || "unknown",
      operation: req.method,
      decision: "auth_failed",
      requestDigest: digestOf(raw),
    });
    log.warn("rejected: inbound-webhook bad or missing signature");
    return deny(res, 401, "invalid_signature");
  }

  let body;
  try {
    body = JSON.parse(raw.toString("utf8"));
  } catch {
    return deny(res, 400, "invalid_json");
  }
  const { sourceHost, method = "POST", runId, workflowManifestDigest, operation, classification, timestamp, nonce, idempotencyKey, data } = body;
  for (const [field, value] of Object.entries({ sourceHost, runId, workflowManifestDigest, timestamp, nonce, idempotencyKey })) {
    if (!value) return deny(res, 400, `missing_${field}`);
  }

  // (2) replay — freshness window, then single-use nonce consumption. This
  // MUST run before the idempotency check: a byte-for-byte replayed request
  // (same nonce reused) is rejected here even though its idempotencyKey may
  // match a cached entry. A legitimate n8n-style retry is a DIFFERENT HTTP
  // delivery attempt — it mints a fresh nonce+timestamp but keeps the same
  // idempotencyKey — so it passes this check and falls through to the cache
  // lookup below instead of being caught here.
  if (!isTimestampFresh(timestamp)) {
    recordEgress(db, {
      connectorId: INBOUND_WEBHOOK_CONNECTOR_ID, destinationHost: sourceHost, operation: method,
      decision: "replay_rejected", requestDigest: digestOf(raw),
    });
    return deny(res, 401, "stale_timestamp");
  }
  if (!checkAndConsumeNonce(nonce)) {
    recordEgress(db, {
      connectorId: INBOUND_WEBHOOK_CONNECTOR_ID, destinationHost: sourceHost, operation: method,
      decision: "replay_rejected", requestDigest: digestOf(raw),
    });
    return deny(res, 401, "replayed_nonce");
  }

  // (3) idempotency — a fresh nonce with a PREVIOUSLY-SEEN idempotencyKey is
  // a legitimate retry (orchestrator retry-on-failure): short-circuit to the
  // cached response rather than re-running connector.send/run-resume.
  const cached = getIdempotentResponse(idempotencyKey);
  if (cached) return sendJson(res, cached.status, cached.body);

  const connector = createInboundWebhookConnector({ db, contract, contractDigest });
  await connector.init({});
  let attestation;
  try {
    ({ attestation } = await connector.send({ sourceHost, method, body: data ?? {}, runId, workflowManifestDigest, operation, classification }));
  } catch (err) {
    const rejected = { status: 403, body: { error: "source_not_allowed" } };
    storeIdempotentResponse(idempotencyKey, rejected);
    return sendJson(res, rejected.status, rejected.body);
  }

  // (4) deny-by-default termination. Absent an explicit "run.resume" grant,
  // the webhook is accepted and attested but NEVER touches the run engine —
  // a human/local caller must still drive /run/resume separately.
  let resumed = false;
  let runState = null;
  const resumeAuthorized = Array.isArray(contract.scopes) && contract.scopes.includes("run.resume");
  if (resumeAuthorized) {
    const row = db.prepare("SELECT * FROM runs WHERE run_id = ?").get(runId);
    if (row && row.state === "awaiting_data") {
      const manifest = JSON.parse(row.manifest_json);
      const kernelStepRunner = createKernelStepRunner();
      const stepRunner = async (step, ctx) => {
        const output = await kernelStepRunner(step, ctx);
        publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
        return output;
      };
      runsInFlight++;
      try {
        // Same gateCheck the authenticated /run/resume route uses — an
        // unsatisfied §27.4 hold re-parks at awaiting_data no matter who
        // called this route or what the contract grants. This route never
        // submits an HA record on the caller's behalf; it only ever
        // re-invokes the SAME re-verifying resume path.
        const result = await executeRun(db, { runId, manifest, dryRun: !!row.dry_run, stepRunner, gateCheck: haGateCheckFor(db) });
        publishRunEvent(runId, { run_id: runId, state: result.state, execution_hash: result.executionHash, held: result.held ?? null });
        runState = result.state;
        resumed = result.state !== "awaiting_data";
      } catch (err) {
        log.error("inbound-webhook: resume failed", { runId, error: String(err?.message || err) });
        runState = "failed";
      } finally {
        runsInFlight--;
      }
    } else if (row) {
      runState = row.state;
    }
  }

  const responseBody = { attestation, resumed, runState, resumeAuthorized };
  storeIdempotentResponse(idempotencyKey, { status: 200, body: responseBody });
  sendJson(res, 200, responseBody);
}

// GET /ha/pending (HELM-HA-1) — every run currently held at a §27.4 gate,
// with what it's waiting on (subject_hash/role/policy/threshold + records
// collected so far) — the approve/reject queue's data source.
function handleHaPending(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const rows = db.prepare("SELECT * FROM runs WHERE state = 'awaiting_data'").all();
  Promise.all(rows.map((row) => findHeldGate(db, row)))
    .then((holds) => {
      const pending = holds.filter(Boolean).map((h) => ({ ...h, records: recordsForSubject(db, h.subjectHash) }));
      sendJson(res, 200, { pending });
    })
    .catch((err) => {
      log.error("ha: pending scan failed", { error: String(err?.message || err) });
      deny(res, 500, "pending_scan_failed");
    });
}

// GET /ha/records?subject_hash=... — the §27.2 evidence trail for one
// subject (read-only, no side effects — matches the D8 GET-is-read-only
// invariant every other route here follows).
function handleHaRecords(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const subjectHash = new URL(req.url, "http://x").searchParams.get("subject_hash");
  if (!subjectHash) return deny(res, 400, "missing_subject_hash");
  sendJson(res, 200, { records: recordsForSubject(db, subjectHash), subject_hash: subjectHash });
}

// POST /ha/records {record} — accept an already-signed §27.2 record (the
// browser mints and signs it with its own local key; helmd never holds a
// human approver's private key). Verifies the signature cryptographically
// against the record's own did:key identity BEFORE storing — a bad
// signature is refused outright, never stored "pending verification".
async function handleHaRecordSubmit(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  const record = body.record ?? body;
  try {
    const { recordId } = await submitHaRecord(db, record);
    sendJson(res, 200, { ok: true, record_id: recordId });
  } catch (err) {
    sendJson(res, 422, { ok: false, error: String(err?.message || err) });
  }
}

// POST /ha/replay {run_id, step_id} — helmd re-executes the named "nodes"
// step itself (kernel-runner.mjs's runKernelNode, the SAME invocation the
// run engine used originally) and compares the freshly-recomputed
// execution_hash to what was recorded. `replay_verified` on the resulting
// countersignature reflects that match ONLY — see ha-gate.mjs recordReplay's
// doc comment for why this can never be inferred or caller-supplied.
async function handleHaReplay(req, res, params, db, haIdentity) {
  if (!db) return deny(res, 503, "engine_unavailable");
  if (!haIdentity) return deny(res, 503, "ha_identity_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  if (!body.run_id || !body.step_id) return deny(res, 400, "missing_run_id_or_step_id");
  try {
    const result = await recordReplay(db, { runId: body.run_id, stepId: body.step_id, checkerIdentity: haIdentity });
    sendJson(res, 200, result);
  } catch (err) {
    sendJson(res, 422, { ok: false, error: String(err?.message || err) });
  }
}

// GET /ha/slot?subject_hash=... — the raw countersignature_slot for a
// subject (maker signature + checker countersignatures incl. replay_verified),
// separate from /ha/records because it's a different schema/artifact.
function handleHaSlot(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const subjectHash = new URL(req.url, "http://x").searchParams.get("subject_hash");
  if (!subjectHash) return deny(res, 400, "missing_subject_hash");
  sendJson(res, 200, { slot: getSlot(db, subjectHash) });
}

// GET /provenance/head (PROV-SNAP-HELM-1) — the daemon's own SPEC.md
// §SNAP-1/§HEAD-1 chain-verify status: whether a state-snapshot chain exists
// yet, its latest snapshot/head seq, and whether the stored head-commit
// chain still verifies (structural laws + each head's own eddsa-jcs-2022
// proof) RIGHT NOW — not merely that one was once signed. Read-only, no
// side effects, matching every other route here.
function handleProvenanceHead(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  provenanceStatus(db)
    .then((status) => sendJson(res, 200, status))
    .catch((err) => {
      log.error("provenance: status check failed", { error: String(err?.message || err) });
      deny(res, 500, "provenance_status_failed");
    });
}

// GET /run/timeline?run_id=... — execution_state transitions straight off
// the journal's run:<id> stream (already the durable, replay-verified
// record — no separate projection table to keep in sync).
function handleRunTimeline(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const runId = new URL(req.url, "http://x").searchParams.get("run_id");
  if (!runId) return sendJson(res, 200, { steps: [] });
  const rows = db.prepare("SELECT entry_json FROM journal WHERE stream_id = ? ORDER BY seq ASC").all(`run:${runId}`);
  const steps = rows.map((row) => {
    const entry = JSON.parse(row.entry_json);
    return { state: entry.state, recorded_at: entry.period_end };
  });
  sendJson(res, 200, { steps });
}

// GET /kernels/:id/card?format=json|html|table|dmn (HELM-P3-E12; table/dmn
// added HELM-P4-A4) — per-kernel validation card generated from vendored
// metadata + committed fixtures. "table" is the read-only decision-table
// view of the same test vectors; "dmn" is its DMN 1.5 XML export.
function handleKernelCard(req, res, params) {
  const format = new URL(req.url, "http://x").searchParams.get("format");
  let card;
  try {
    card = buildKernelCard(params.id);
  } catch {
    return deny(res, 404, "kernel_not_found");
  }
  if (format === "html") return sendHtml(res, 200, renderKernelCardHtml(card));
  if (format === "table") return sendHtml(res, 200, renderKernelDecisionTableHtml(card));
  if (format === "dmn") return sendXml(res, 200, buildKernelDecisionTableDmn(card));
  sendJson(res, 200, card);
}

// GET /workflows/:id/euc-entry?format=json|html&owner=&purpose=&control_description=&last_validated=
// (HELM-P3-E12) — one-click EUC register entry for a compiled workflow.
// owner/purpose/control_description/last_validated aren't persisted
// anywhere in helm today (see hub/euc-register.mjs) — caller supplies them
// per export.
function handleEucEntry(req, res, params) {
  const q = new URL(req.url, "http://x").searchParams;
  const format = q.get("format") === "html" ? "html" : "json";
  let entry;
  try {
    entry = buildEucEntry(params.id, {
      owner: q.get("owner") || undefined,
      purpose: q.get("purpose") || undefined,
      controlDescription: q.get("control_description") || undefined,
      lastValidated: q.get("last_validated") || undefined,
    });
  } catch {
    return deny(res, 404, "workflow_not_found");
  }
  if (format === "html") return sendHtml(res, 200, renderEucEntryHtml(entry));
  sendJson(res, 200, entry);
}

// GET /workflows/:id/export[?format=bpmn] (HELM-P3-W11; bpmn format added
// HELM-BPMN-WIRE-1) — the versioned, secrets-stripped, kernel-hash-pinned
// `.helm.json` file by default, or the pack's BPMN 2.0 XML diagram
// (hub/bpmn-export.mjs, previously CLI-only via scripts/export-bpmn.mjs)
// with ?format=bpmn. Both are read-only re-shapes of an already compiled
// pack, same immutable-catalog discipline as handleEucEntry above — no
// consent ticket, since this exports only a diagram/shape of a workflow the
// caller already holds (no secret material, no vault/connector access; read
// tier per the standard bearer-token gate in createHelmServer, same as the
// .helm.json export it shares a route with).
function handleWorkflowExportRoute(req, res, params) {
  const format = new URL(req.url, "http://x").searchParams.get("format");
  if (format === "bpmn") {
    const pack = getPack(params.id);
    if (!pack) return deny(res, 404, "workflow_not_found");
    return sendXml(res, 200, exportBpmn(pack.manifest));
  }
  let doc;
  try {
    doc = buildWorkflowExport(params.id);
  } catch {
    return deny(res, 404, "workflow_not_found");
  }
  sendJson(res, 200, doc);
}

// POST /workflows/import {export: <parsed .helm.json contents>} — HELM-P3-W11.
// Validation-only: packs are compile-time-immutable (D2 zero-dep, same
// discipline as packs.mjs), so importing never writes anything — the caller
// gets back exactly the {ok, workflow_id, manifest, kernelPins} / refused
// shape parseWorkflowExport() always returns, never a thrown error.
async function handleWorkflowImport(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  const result = parseWorkflowExport(body.export ?? body);
  sendJson(res, result.ok ? 200 : 422, result);
}

// POST /migration/import {bundle, raw_entries, fresh_reauth} — P3-M7
// daemon-mediated import path. Reachable only through the normal bearer-token
// gate below (never the pre-auth detection routes) — a paired browser is
// already the trust boundary; migration-import.mjs's own freshReauth check
// additionally refuses a bundle whose caller skipped the post-proof re-auth.
async function handleMigrationImport(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  if (!body.bundle || !Array.isArray(body.raw_entries)) return deny(res, 400, "missing_bundle_or_raw_entries");
  const result = importMigrationBundle(db, {
    bundle: body.bundle,
    rawEntries: body.raw_entries,
    freshReauth: body.fresh_reauth === true,
    overwrite: body.overwrite === true,
  });
  if (!result.ok) return sendJson(res, 422, result);
  sendJson(res, 200, result);
}

// GET /matters[?status=intake|working|closed] (HELM-MATTER-H1): list matters,
// newest-created last, optionally filtered by status.
function handleMattersList(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const status = new URL(req.url, "http://x").searchParams.get("status");
  sendJson(res, 200, { matters: listMatters(db, status ? { status } : {}) });
}

// POST /matters {status?, entity, parties?, deadlines?, bindings?, narrative?}
// (HELM-MATTER-H1): create a matter. matter_id/created_at/updated_at/
// manifest_digest are always server-assigned. Refused (422) if the resulting
// manifest fails the frozen §2 schema or any non-external_reference binding
// doesn't resolve to a known local artifact (§3) — matter-store.mjs owns
// both checks and never partially writes.
async function handleMattersCreate(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  try {
    sendJson(res, 200, { ok: true, matter: createMatter(db, body) });
  } catch (err) {
    sendJson(res, 422, { ok: false, error: String(err?.message || err) });
  }
}

// GET /matters/{id} (HELM-MATTER-H1).
function handleMatterGet(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const matter = getMatter(db, params.id);
  if (!matter) return deny(res, 404, "matter_not_found");
  sendJson(res, 200, { matter });
}

// POST /matters/{id}/update {status?, entity?, parties?, deadlines?,
// bindings?, narrative?} (HELM-MATTER-H1): a present field replaces the
// existing member wholesale; an omitted field carries forward unchanged.
// Same §2/§3 refusal discipline as create, plus matter-store.mjs's own
// append-only guard on already-done deadlines.
//
// HELM-MATTER-H2: routes through closeMatter() rather than updateMatter()
// directly — additive wrapper, same update semantics/errors, that also
// emits+persists the signed closeout export automatically the ONE time this
// call is what actually transitions status into "closed" (never on a later
// edit to an already-closed matter). `keys` (server's identityKeys) is
// threaded in by createHelmServer's route override below; without it the
// status change still applies in full, simply with no export (closeMatter's
// own doc comment).
async function handleMatterUpdate(req, res, params, db, keys) {
  if (!db) return deny(res, 503, "engine_unavailable");
  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return deny(res, 400, "invalid_json");
  }
  try {
    const { matter, export: exported } = closeMatter(db, params.id, body, keys);
    sendJson(res, 200, { ok: true, matter, ...(exported ? { export: exported } : {}) });
  } catch (err) {
    const status = /unknown matter_id/.test(String(err?.message)) ? 404 : 422;
    sendJson(res, status, { ok: false, error: String(err?.message || err) });
  }
}

// GET /matters/{id}/export (HELM-MATTER-H2): reads back the signed
// bundle-of-bundles export already emitted when the matter closed (via the
// route above) — pure read, never assembles or signs anything itself. 404 if
// the matter was never closed with signing keys available (never closed at
// all, or closed by a caller that omitted keys).
function handleMatterExportGet(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  const exported = getMatterExport(db, params.id);
  if (!exported) return deny(res, 404, "matter_export_not_found");
  sendJson(res, 200, { export: exported });
}

// POST /matters/{id}/delete (HELM-MATTER-H1): removes the matter's local
// INDEX row only — a matter never holds primary evidence (bindings are
// hash references, never payload copies), so this cannot lose or alter any
// run/evidence-bundle/approval-record a deleted matter pointed at.
function handleMatterDelete(req, res, params, db) {
  if (!db) return deny(res, 503, "engine_unavailable");
  if (!deleteMatter(db, params.id)) return deny(res, 404, "matter_not_found");
  sendJson(res, 200, { ok: true });
}

// Exported (not just used internally) so scripts/gen-openapi.mjs (HELM-P4-B2)
// can derive the OpenAPI doc from the SAME route table the server actually
// dispatches on, instead of a hand-copied list that can silently drift.
export const ROUTES = {
  "GET /health": handleHealth,
  "GET /version-check": (req, res) => handleVersionCheck(req, res, DEFAULT_VERSION_CHECK_URL),
  "GET /events": handleEvents,
  "POST /events/ticket": handleEventsTicket,
  "POST /evidence/export/ticket": handleEvidenceExportTicket,
  "GET /signer/config": handleSignerConfigGet,
  "POST /signer/config/ticket": handleSignerConfigTicket,
  "POST /signer/config": handleSignerConfigUpdate,
  "POST /vault/connections/begin": handleBeginConnection,
  "GET /vault/connections": handleListConnections,
  "GET /connectors": (req, res) => handleListConnectors(req, res, null, null, DEFAULT_INBOUND_WEBHOOK_CONTRACT_PATH),
  "GET /workflows": handleWorkflows,
  "GET /templates": handleTemplates,
  "GET /workflow-manifest": handleWorkflowManifest,
  "POST /run/start": handleRunStart,
  "POST /run/resume": handleRunResume,
  "GET /run/timeline": handleRunTimeline,
  "POST /pair/redeem": handlePairRedeem,
  "POST /pair/relink": handlePairRelink,
  "POST /migration/import": handleMigrationImport,
  "POST /workflows/import": handleWorkflowImport,
  "GET /autostart": handleAutostartStatus,
  "POST /autostart": handleAutostartSet,
  "GET /ha/pending": handleHaPending,
  "GET /ha/records": handleHaRecords,
  "GET /ha/slot": handleHaSlot,
  "POST /ha/records": handleHaRecordSubmit,
  "GET /provenance/head": handleProvenanceHead,
  "GET /matters": handleMattersList,
  "POST /matters": handleMattersCreate,
  // HELM-H9: MCP v2 JSON-RPC endpoint, same Host+Origin+Bearer gate as every
  // other route here (row: "same bearer-token auth as REST"). GET/DELETE are
  // registered too, deliberately — SEP-2567 (final, no delta) removed the
  // SSE/session GET stream from the MCP transport entirely, so those methods
  // must answer 405, never fall through to the generic 404 a truly-unknown
  // path gets.
  "POST /mcp": handleMcp,
  "GET /mcp": handleMcpMethodNotAllowed,
  "DELETE /mcp": handleMcpMethodNotAllowed,
};

// docPath: the OpenAPI-style templated path (gen-openapi.mjs has no way to
// recover `{id}` from a compiled RegExp, so it rides along here).
export const DYNAMIC_ROUTES = [
  { method: "GET", pattern: /^\/vault\/connections\/flow\/(?<flowId>[^/]+)$/, docPath: "/vault/connections/flow/{flowId}", handler: handleFlowStatus },
  { method: "POST", pattern: /^\/vault\/connections\/(?<id>[^/]+)\/revoke$/, docPath: "/vault/connections/{id}/revoke", handler: handleRevoke },
  { method: "GET", pattern: /^\/kernels\/(?<id>[^/]+)\/card$/, docPath: "/kernels/{id}/card", handler: handleKernelCard },
  { method: "GET", pattern: /^\/workflows\/(?<id>[^/]+)\/euc-entry$/, docPath: "/workflows/{id}/euc-entry", handler: handleEucEntry },
  { method: "GET", pattern: /^\/workflows\/(?<id>[^/]+)\/export$/, docPath: "/workflows/{id}/export", handler: handleWorkflowExportRoute },
  { method: "GET", pattern: /^\/templates\/(?<slug>[^/]+)$/, docPath: "/templates/{slug}", handler: handleTemplateDetail },
  { method: "GET", pattern: /^\/matters\/(?<id>[^/]+)$/, docPath: "/matters/{id}", handler: handleMatterGet },
  { method: "POST", pattern: /^\/matters\/(?<id>[^/]+)\/update$/, docPath: "/matters/{id}/update", handler: handleMatterUpdate },
  { method: "POST", pattern: /^\/matters\/(?<id>[^/]+)\/delete$/, docPath: "/matters/{id}/delete", handler: handleMatterDelete },
  { method: "GET", pattern: /^\/matters\/(?<id>[^/]+)\/export$/, docPath: "/matters/{id}/export", handler: handleMatterExportGet },
];

export function createHelmServer({
  port,
  allowedOrigin,
  token,
  db = null,
  identityKeys = null,
  haIdentity = null,
  versionCheckUrl = DEFAULT_VERSION_CHECK_URL,
  exitFn = () => process.exit(0),
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
  // §18.2: called after every request clears the Host+Origin+Bearer gate,
  // before it reaches a handler. index.mjs wires this to the idle timer's
  // reset() — kept as a no-op default so every existing test/caller that
  // doesn't care about idle shutdown is unaffected.
  onAuthenticated = () => {},
  // HELM-INBOUND-WEBHOOK-1: overridable so tests can point at a contract
  // fixture that grants "run.resume" without touching the shipped default
  // (which never grants it — deny-by-default).
  inboundWebhookContractPath = DEFAULT_INBOUND_WEBHOOK_CONTRACT_PATH,
  // HELM-AUTOSTART-1: injectable so a test can exercise the real route
  // dispatch without writing to the developer's actual registry / Start Menu.
  autostartOps = DEFAULT_AUTOSTART_OPS,
}) {
  const { contract: webhookContract, contractDigest: webhookContractDigest } = loadContract(inboundWebhookContractPath);
  const routes = {
    ...ROUTES,
    "GET /health": (req, res) => handleHealth(req, res, {}, db, idleTimeoutMs),
    "GET /version-check": (req, res) => handleVersionCheck(req, res, versionCheckUrl),
    "POST /ha/replay": (req, res, params, reqDb) => handleHaReplay(req, res, params, reqDb, haIdentity),
    "POST /shutdown": (req, res, params, reqDb) => handleShutdown(req, res, params, reqDb, exitFn),
    "POST /pair/relink": (req, res, params, reqDb) => handlePairRelink(req, res, params, reqDb, port, token, identityKeys),
    "GET /autostart": (req, res, params, reqDb) => handleAutostartStatus(req, res, params, reqDb, autostartOps),
    "POST /autostart": (req, res, params, reqDb) => handleAutostartSet(req, res, params, reqDb, autostartOps),
    "GET /connectors": (req, res, params, reqDb) => handleListConnectors(req, res, params, reqDb, inboundWebhookContractPath),
  };
  // HELM-MATTER-H2: DYNAMIC_ROUTES entries have no per-instance override
  // mechanism of their own (unlike `routes` above) — this mirrors that
  // pattern for the one dynamic handler that needs a closure value
  // (identityKeys, to sign the closeout export). Every other dynamic route
  // passes through unchanged.
  const dynamicRoutes = DYNAMIC_ROUTES.map((route) =>
    route.handler === handleMatterUpdate
      ? { ...route, handler: (req, res, params, reqDb) => handleMatterUpdate(req, res, params, reqDb, identityKeys) }
      : route
  );
  const server = createServer((req, res) => {
    if (!checkHost(req, port)) {
      log.warn("rejected: host mismatch", { host: req.headers.host, path: logPath(req) });
      return deny(res, 403, "host_mismatch");
    }

    const pathname = new URL(req.url, `http://x`).pathname;
    // Static UI shell: served pre-CORS, pre-auth (see static.mjs for why).
    // Only exact allowlisted paths match — anything else falls through to
    // the API router below and gets its normal 404.
    if (serveStatic(req, res, pathname)) return;

    // Detection surface (P3-D3/D9): handled BEFORE the normal Origin+bearer
    // gate — these two routes have their own narrower origin check
    // (loopback UI OR the fixed hosted origin) and never require a token.
    if (DETECTION_PATHS.has(pathname)) {
      if (req.method === "OPTIONS") return handleDetectionPreflight(req, res, allowedOrigin);
      if (req.method === "GET") return handleDetectionRoute(req, res, pathname, identityKeys, allowedOrigin);
      return deny(res, 404, "not_found");
    }

    // HELM-INBOUND-WEBHOOK-1: also handled BEFORE the normal Origin+bearer
    // gate, for the opposite reason from detection surface above — the
    // caller here has neither the browser Origin nor the daemon's pairing
    // token. Its own authentication (HMAC-over-raw-body) lives entirely
    // inside handleInboundWebhook; Host still applies (checked above), Origin
    // and bearer do not.
    if (pathname === INBOUND_WEBHOOK_PATH) {
      if (req.method !== "POST") return deny(res, 404, "not_found");
      return handleInboundWebhook(req, res, db, webhookContract, webhookContractDigest);
    }

    if (!checkOrigin(req, allowedOrigin)) {
      log.warn("rejected: origin mismatch", { origin: req.headers.origin, path: pathname });
      return deny(res, 403, "origin_mismatch");
    }
    applyCors(res, allowedOrigin);

    if (req.method === "OPTIONS") {
      // Preflight: browsers never send Authorization on OPTIONS. Host+Origin
      // checks above already gate this; the real request still needs a token.
      res.writeHead(204);
      return res.end();
    }

    const auth = req.headers.authorization || "";
    let presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    // EventSource can't set an Authorization header. D8 loopback bind means
    // this only ever reaches 127.0.0.1, but per HELM-UX-1 §7.4 the durable
    // bearer must not become a permanent query-string fixture — so this
    // route accepts a short-lived, single-use ticket (POST /events/ticket,
    // minted over an authenticated call) instead of the token itself.
    if (!presented && req.method === "GET" && pathname === "/events") {
      const ticket = new URL(req.url, "http://x").searchParams.get("ticket") || "";
      if (ticket && redeemStreamTicket(ticket)) presented = token;
    }
    if (!tokenMatches(token, presented)) {
      // HELM-REPAIR-LINK-1 (HELM-PAIR-DIAG-1 proposal 3): a browser tab
      // auto-GETs /favicon.ico on every load and can never attach a custom
      // Authorization header to it (no favicon entry in UI_ASSETS), so this
      // 401 fires on EVERY page load — paired or not, healthy or not — with
      // zero diagnostic signal, drowning real 401s during triage (measured
      // directly in HELM-PAIR-DIAG-1: ~1/sec). log.mjs has no level below
      // "warn" to demote it to, so this skips the log line entirely for this
      // one well-understood, zero-signal path rather than adding a new log
      // level for a single caller — every OTHER rejected path still warns.
      if (pathname !== "/favicon.ico") {
        log.warn("rejected: bad or missing token", { path: pathname });
      }
      return deny(res, 401, "unauthorized");
    }
    onAuthenticated();

    const handler = routes[`${req.method} ${pathname}`];
    if (handler) return handler(req, res, {}, db);

    for (const route of dynamicRoutes) {
      if (route.method !== req.method) continue;
      const match = pathname.match(route.pattern);
      if (match) return route.handler(req, res, match.groups || {}, db);
    }
    return deny(res, 404, "not_found");
  });
  server.listen(port, "127.0.0.1");
  return server;
}

// P3-D9: helmd must refuse to start on a squatted port, cleanly — never
// silently retry on a different port, never crash with a raw stack trace.
// Callers attach this immediately after createHelmServer(); Node's error
// emission is async (next-tick at the earliest) so there's no race between
// server.listen() above and the listeners this attaches.
export function bindOrExit(server, port) {
  return new Promise((resolve) => {
    server.once("listening", () => resolve(true));
    server.once("error", (err) => {
      if (err.code === "EADDRINUSE") {
        log.error(`port ${port} is already in use — refusing to start (never falls back to a different port)`, { port });
      } else {
        log.error("helmd failed to start", { error: String(err?.message || err) });
      }
      resolve(false);
    });
  });
}
