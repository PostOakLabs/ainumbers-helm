// Loopback REST + SSE server. D8 hardening, in order, on every request:
//   1. Host header must exactly equal 127.0.0.1:<port>        (DNS-rebinding defense)
//   2. Origin header must exactly equal the configured origin  (no wildcard CORS)
//   3. Authorization: Bearer <token> must match                (pairing token)
// GET handlers are read-only by construction — no side effects on GET.
import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { tokenMatches } from "./token.mjs";
import { log } from "./log.mjs";
import { startFlow, getFlowStatus, listConnections, revokeConnection, isSecureEndpoint } from "./oauth-pkce.mjs";
import { serveStatic } from "./static.mjs";
import { listPacks, getPack } from "./packs.mjs";
import { executeRun } from "./run.mjs";
import { createKernelStepRunner } from "./kernel-runner.mjs";
import { publishRunEvent, subscribeRunEvents } from "./event-bus.mjs";
import { buildKernelCard, buildEucEntry } from "./euc-register.mjs";
import { renderKernelCardHtml, renderEucEntryHtml } from "../ui/lib/euc-html.mjs";

const START = Date.now();

function checkHost(req, port) {
  return req.headers.host === `127.0.0.1:${port}`;
}

function checkOrigin(req, allowedOrigin) {
  return req.headers.origin === allowedOrigin;
}

function applyCors(res, allowedOrigin) {
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
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

function handleHealth(req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok", uptimeMs: Date.now() - START }));
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

// POST /run/start {workflow_id, dry_run} — kicks off the H4 run engine
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
  const workflowId = body.workflow_id;
  if (!workflowId) return deny(res, 400, "missing_workflow_id");
  const pack = getPack(workflowId);
  if (!pack) return deny(res, 404, "workflow_not_found");

  const runId = randomUUID();
  const dryRun = !!body.dry_run;
  const kernelStepRunner = createKernelStepRunner();
  const stepRunner = async (step, ctx) => {
    const output = await kernelStepRunner(step, ctx);
    publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
    return output;
  };

  executeRun(db, { runId, manifest: pack.manifest, dryRun, stepRunner })
    .then((result) => publishRunEvent(runId, { run_id: runId, state: result.state, execution_hash: result.executionHash }))
    .catch((err) => {
      log.error("run engine: run failed", { runId, workflowId, error: String(err?.message || err) });
      publishRunEvent(runId, { run_id: runId, state: "failed", error: String(err?.message || err) });
    });

  sendJson(res, 200, { run_id: runId, state: "queued" });
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

// GET /kernels/:id/card?format=json|html (HELM-P3-E12) — per-kernel
// validation card generated from vendored metadata + committed fixtures.
function handleKernelCard(req, res, params) {
  const format = new URL(req.url, "http://x").searchParams.get("format") === "html" ? "html" : "json";
  let card;
  try {
    card = buildKernelCard(params.id);
  } catch {
    return deny(res, 404, "kernel_not_found");
  }
  if (format === "html") return sendHtml(res, 200, renderKernelCardHtml(card));
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

const ROUTES = {
  "GET /health": handleHealth,
  "GET /events": handleEvents,
  "POST /vault/connections/begin": handleBeginConnection,
  "GET /vault/connections": handleListConnections,
  "GET /workflows": handleWorkflows,
  "GET /workflow-manifest": handleWorkflowManifest,
  "POST /run/start": handleRunStart,
  "GET /run/timeline": handleRunTimeline,
};

const DYNAMIC_ROUTES = [
  { method: "GET", pattern: /^\/vault\/connections\/flow\/(?<flowId>[^/]+)$/, handler: handleFlowStatus },
  { method: "POST", pattern: /^\/vault\/connections\/(?<id>[^/]+)\/revoke$/, handler: handleRevoke },
  { method: "GET", pattern: /^\/kernels\/(?<id>[^/]+)\/card$/, handler: handleKernelCard },
  { method: "GET", pattern: /^\/workflows\/(?<id>[^/]+)\/euc-entry$/, handler: handleEucEntry },
];

export function createHelmServer({ port, allowedOrigin, token, db = null }) {
  const server = createServer((req, res) => {
    if (!checkHost(req, port)) {
      log.warn("rejected: host mismatch", { host: req.headers.host, path: req.url });
      return deny(res, 403, "host_mismatch");
    }

    const pathname = new URL(req.url, `http://x`).pathname;
    // Static UI shell: served pre-CORS, pre-auth (see static.mjs for why).
    // Only exact allowlisted paths match — anything else falls through to
    // the API router below and gets its normal 404.
    if (serveStatic(req, res, pathname)) return;

    if (!checkOrigin(req, allowedOrigin)) {
      log.warn("rejected: origin mismatch", { origin: req.headers.origin, path: req.url });
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
    // this token only ever reaches 127.0.0.1 — carrying it in the query
    // string is a deliberate, narrow exception scoped to this one GET route
    // (matches ui/views/run.mjs's openProgressStream; flagged for HELM-R1).
    if (!presented && req.method === "GET" && pathname === "/events") {
      presented = new URL(req.url, "http://x").searchParams.get("token") || "";
    }
    if (!tokenMatches(token, presented)) {
      log.warn("rejected: bad or missing token", { path: req.url });
      return deny(res, 401, "unauthorized");
    }

    const handler = ROUTES[`${req.method} ${pathname}`];
    if (handler) return handler(req, res, {}, db);

    for (const route of DYNAMIC_ROUTES) {
      if (route.method !== req.method) continue;
      const match = pathname.match(route.pattern);
      if (match) return route.handler(req, res, match.groups || {}, db);
    }
    return deny(res, 404, "not_found");
  });
  server.listen(port, "127.0.0.1");
  return server;
}
