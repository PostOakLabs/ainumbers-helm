// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-H9: local MCP v2 endpoint. Stateless (D7) — every request stands
// alone, keyed to a Helm run_id (a run IS the task, per the Tasks
// extension), never to an MCP session. There is no server-held session
// state here at all: SEP-2567 (final, no delta from RC) removed the
// GET+Mcp-Session-Id stream from the transport entirely, and this daemon
// never minted or echoed one even before that landed.
//
// Wire values below are re-confirmed against the FINAL 2026-07-28 spec text
// (not the RC) — reused verbatim from board/done/MCP728-A0.md, which the
// whole MCP-728 Track A band already shipped against on both site workers.
// Do not re-derive them here.
//
// READ/RUN ONLY, per Tim's amendment via phil (research/PERSONA-phil-2026-07-25.md,
// HELM-UX-BUILD-SPEC.md §19.4): no connector.authorize reachable through
// this endpoint at all, and evidence.export is deliberately NOT in the same
// trust tier as the read/run tools — see the consent-ticket check in its
// handler and token.mjs's createExportTicket/redeemExportTicket doc comment.
import { getPack, listPacks } from "./packs.mjs";
import { listTemplates, getTemplate, buildTemplateManifest } from "./templates.mjs";
import { manifestDigest, replayExecutionHash } from "./run.mjs";
import { startWorkflowRun, resolveRunManifest } from "./run-actions.mjs";
import { redeemExportTicket } from "./token.mjs";
import { log } from "./log.mjs";

export const MCP_PROTOCOL_VERSION = "2026-07-28";
// HELM-MCP-FALLBACK-1: dual-era window, reusing anchor-suite's shipped shape
// verbatim (board/done/MCP728-CONFORM-FIX-1.md, anchor-suite/src/worker.mjs)
// rather than compute's SDK-header-strip shape. Anchor is the closer analogue:
// both it and helm are hand-rolled zero-dep HTTP servers with no MCP SDK
// transport to intercept, so "advertise multiple versions, era-gate the
// 2026-07-28-only enforcement" applies directly here; compute's fix instead
// patches around an SDK transport helm does not have.
const LEGACY_PROTOCOL_VERSION = "2025-06-18";
const SUPPORTED_PROTOCOL_VERSIONS = [MCP_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION];

const TASKS_EXTENSION = "io.modelcontextprotocol/tasks";
const META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO = "io.modelcontextprotocol/serverInfo";
const SERVER_INFO = { name: "co.ainumbers/helm", version: MCP_PROTOCOL_VERSION };

// SEP-2243 (final): three REQUIRED-for-compliance headers. MCP-Protocol-Version
// and Mcp-Method apply to every request; Mcp-Name additionally applies to
// tools/call (our only method in that named set — resources/read and
// prompts/get aren't implemented here). Missing, mismatched, or invalid-char
// -> -32020 HeaderMismatch + HTTP 400 (Q1, re-confirmed against final text).
//
// The sentinel is the spec's, verbatim: `Mcp-Name: =?base64?{Base64EncodedValue}?=`.
// Transports/Value Encoding: "The prefix `=?base64?` and suffix `?=` indicate that
// the value is Base64-encoded. These markers are case-sensitive and MUST appear
// exactly as shown (lowercase)." Hence no `/i` flag.
//
// HELM-MCP-CONFORM-1 (2026-07-30): this pattern previously required an
// RFC-2047-style `B?` encoding token (`=?base64?B?…?=`) that the MCP sentinel
// does not have, so a conforming client was rejected with -32020 and the only
// accepted form was one no conforming client emits. The legacy `B?` form is NOT
// retained: a repo-wide search found zero emitters outside this file and its own
// test, the endpoint shipped hours earlier with nothing depending on it, and a
// second accepted encoding is a second canon.
const BASE64_SENTINEL = /^=\?base64\?([A-Za-z0-9+/=]+)\?=$/;

function decodeHeaderValue(v) {
  if (typeof v !== "string") return v;
  const m = v.match(BASE64_SENTINEL);
  if (!m) return v;
  try {
    return Buffer.from(m[1], "base64").toString("utf8");
  } catch {
    return null; // malformed sentinel — caller treats this as a mismatch
  }
}

function hasInvalidChar(v) {
  // eslint-disable-next-line no-control-regex
  return typeof v !== "string" || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(v);
}

function jsonRpcError(id, code, message, data) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data !== undefined ? { data } : {}) } };
}

// Per-response protocol fields (/basic): servers SHOULD carry
// io.modelcontextprotocol/serverInfo in every result's _meta so a client can
// identify the server without any prior connection state.
function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id, result: { ...result, _meta: { ...(result._meta || {}), [META_SERVER_INFO]: SERVER_INFO } } };
}

function sendJson(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
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

// GET/DELETE /mcp: SEP-2567 (final, no delta) — sessions and the GET stream
// are gone from the transport. Registered explicitly in server.mjs's ROUTES
// so these two methods get a real 405 rather than falling through to the
// router's generic 404 for a truly-unknown path.
export function handleMcpMethodNotAllowed(req, res) {
  res.writeHead(405, { "Content-Type": "application/json", Allow: "POST" });
  res.end(JSON.stringify({ error: "method_not_allowed" }));
}

const TOOLS = [
  { name: "catalog.search", description: "Search the compiled workflow-pack + template catalog by name/outcome/title substring.", inputSchema: { type: "object", properties: { query: { type: "string" } } } },
  { name: "workflow.describe", description: "Human-facing summary of a compiled workflow pack (name, outcome, manifest digest).", inputSchema: { type: "object", properties: { workflow_id: { type: "string" } }, required: ["workflow_id"] } },
  { name: "workflow.manifest_get", description: "The raw DAG manifest (nodes/gates/actions) for a compiled workflow pack.", inputSchema: { type: "object", properties: { workflow_id: { type: "string" } }, required: ["workflow_id"] } },
  { name: "workflow.dry_run", description: "Start a side-effect-free dry run of a workflow or template. Returns a Task; poll tasks/get with the returned taskId.", inputSchema: { type: "object", properties: { workflow_id: { type: "string" }, template_slug: { type: "string" } } } },
  { name: "workflow.run", description: "Start a real run of a workflow or template. Returns a Task; poll tasks/get with the returned taskId.", inputSchema: { type: "object", properties: { workflow_id: { type: "string" }, template_slug: { type: "string" } } } },
  { name: "artifact.get", description: "Fetch a run's digest-level artifact: state, execution_hash, per-step digests.", inputSchema: { type: "object", properties: { run_id: { type: "string" } }, required: ["run_id"] } },
  { name: "artifact.verify", description: "Recompute a completed run's execution_hash from persisted state and compare to the recorded value (deterministic replay).", inputSchema: { type: "object", properties: { run_id: { type: "string" } }, required: ["run_id"] } },
  {
    name: "evidence.export",
    description: "Export a run's digest-level evidence record. Requires a one-time consent ticket minted by the paired UI (POST /evidence/export/ticket) — NOT reachable from tools/call alone. Phase-1 scope: digest-level record (hash_verified), not yet the full signed §26.6 bundle.zip.",
    inputSchema: { type: "object", properties: { run_id: { type: "string" }, ticket: { type: "string" } }, required: ["run_id", "ticket"] },
  },
];

// Tasks extension: a CreateTaskResult carries ttlMs and pollIntervalMs. Runs are
// journalled durably and never expire on their own, so ttlMs is advisory only.
const TASK_TTL_MS = 86_400_000;
const TASK_POLL_INTERVAL_MS = 1000;

// The two run-starting tools are the only ones that can return resultType:"task",
// so they are the only ones gated on the client having declared the extension.
const TASK_RETURNING_TOOLS = new Set(["workflow.dry_run", "workflow.run"]);

function taskStatusFor(state) {
  // Maps run.mjs's Phase-1 lifecycle onto the Tasks extension's status enum.
  if (state === "completed") return "completed";
  if (state === "failed" || state === "cancelled") return "failed";
  if (state === "awaiting_data") return "input_required";
  return "working"; // draft/validated/queued/running
}

function runRow(db, runId) {
  return db.prepare("SELECT * FROM runs WHERE run_id = ?").get(runId);
}

function stepDigestsFor(db, runId) {
  return db.prepare("SELECT step_id, output_digest, completed_at FROM step_results WHERE run_id = ? ORDER BY completed_at ASC").all(runId);
}

// Every successful tool result carries resultType (spec MUST) drawn from the
// DEFINED set only: core /basic defines "complete" and "input_required"; the
// Tasks extension adds "task". "A resultType of any value unrecognized by the
// client MUST be considered invalid." HELM-MCP-CONFORM-1 (2026-07-30): every
// handler here previously returned the undefined value "success", making every
// helm result invalid to a conforming client. Read-only work that has already
// finished is "complete"; the two run-starting tools are "task".
//
// callTool returns {resultType, payload}: the payload is the structured tool
// output, kept separate so it can go in structuredContent without the
// protocol-level resultType leaking into the tool's own data.
function callTool(db, name, args = {}) {
  switch (name) {
    case "catalog.search": {
      const q = (args.query || "").toLowerCase();
      const workflows = listPacks().filter((w) => !q || w.workflow_id.includes(q) || w.name?.toLowerCase().includes(q) || w.outcome?.toLowerCase().includes(q));
      const templates = listTemplates().filter((t) => !q || t.slug.includes(q) || t.title?.toLowerCase().includes(q) || t.blurb?.toLowerCase().includes(q));
      return { resultType: "complete", payload: { workflows, templates } };
    }
    case "workflow.describe": {
      const pack = getPack(args.workflow_id);
      if (!pack) throw { code: -32602, message: "workflow_not_found" };
      return { resultType: "complete", payload: { workflow_id: pack.workflow_id, name: pack.name, outcome: pack.outcome, manifest_digest: manifestDigest(pack.manifest) } };
    }
    case "workflow.manifest_get": {
      const pack = getPack(args.workflow_id);
      if (!pack) throw { code: -32602, message: "workflow_not_found" };
      return { resultType: "complete", payload: { manifest: pack.manifest } };
    }
    case "workflow.dry_run":
    case "workflow.run": {
      let started;
      try {
        started = startWorkflowRun(db, { workflowId: args.workflow_id, templateSlug: args.template_slug, dryRun: name === "workflow.dry_run" });
      } catch (err) {
        if (err && err.status) throw { code: -32602, message: err.error };
        throw err;
      }
      return { resultType: "task", task: { taskId: started.runId, status: "working", ttlMs: TASK_TTL_MS, pollIntervalMs: TASK_POLL_INTERVAL_MS } };
    }
    case "artifact.get": {
      if (!args.run_id) throw { code: -32602, message: "missing_run_id" };
      const row = runRow(db, args.run_id);
      if (!row) throw { code: -32602, message: "run_not_found" };
      return {
        resultType: "complete",
        payload: {
          run_id: row.run_id,
          state: row.state,
          execution_hash: row.execution_hash,
          workflow_manifest_digest: row.workflow_manifest_digest,
          steps: stepDigestsFor(db, row.run_id),
        },
      };
    }
    case "artifact.verify": {
      if (!args.run_id) throw { code: -32602, message: "missing_run_id" };
      const row = runRow(db, args.run_id);
      if (!row) throw { code: -32602, message: "run_not_found" };
      if (row.state !== "completed") return { resultType: "complete", payload: { valid: false, reason: `run_not_completed:${row.state}` } };
      let recomputed;
      try {
        recomputed = replayExecutionHash(db, args.run_id);
      } catch (err) {
        return { resultType: "complete", payload: { valid: false, reason: String(err?.message || err) } };
      }
      return { resultType: "complete", payload: { valid: recomputed === row.execution_hash, execution_hash: row.execution_hash, recomputed } };
    }
    case "evidence.export": {
      if (!args.run_id) throw { code: -32602, message: "missing_run_id" };
      if (!args.ticket || !redeemExportTicket(args.ticket)) {
        throw { code: -32602, message: "consent_required — mint a ticket via POST /evidence/export/ticket from the paired UI first" };
      }
      const row = runRow(db, args.run_id);
      if (!row) throw { code: -32602, message: "run_not_found" };
      return {
        resultType: "complete",
        payload: {
          trust_label: "hash_verified",
          run_id: row.run_id,
          state: row.state,
          execution_hash: row.execution_hash,
          workflow_manifest_digest: row.workflow_manifest_digest,
          steps: stepDigestsFor(db, row.run_id),
        },
      };
    }
    default:
      throw { code: -32602, message: `unknown_tool:${name}` };
  }
}

// Did this request declare the Tasks extension in its per-request capabilities?
// Tasks: "Before returning a CreateTaskResult, verify that the client included
// the extension in its per-request capabilities. Never return a task to a client
// that did not declare support."
function declaresTasks(params) {
  const caps = params?._meta?.[META_CLIENT_CAPABILITIES];
  return Boolean(caps && caps.extensions && Object.prototype.hasOwnProperty.call(caps.extensions, TASKS_EXTENSION));
}

// -32021 MissingRequiredClientCapability, HTTP 400, data.requiredCapabilities
// listing what was missing (/basic, Per-request protocol fields).
function missingCapability(id, capability) {
  return { status: 400, body: jsonRpcError(id, -32021, "MissingRequiredClientCapability", { requiredCapabilities: { extensions: { [capability]: {} } } }) };
}

// Returns {status, body}, or null for an unimplemented method (caller answers
// HTTP 404 + -32601 for a modern-era request, 200 + -32601 for a legacy one —
// per the transport's Protocol Version Header section and anchor's shipped
// dual-era shape).
function dispatch(db, req_, negotiatedVersion) {
  const { id, method, params } = req_;
  switch (method) {
    case "initialize":
      return { status: 200, body: jsonRpcResult(id, {
        resultType: "complete",
        protocolVersion: negotiatedVersion,
        capabilities: { tools: {}, extensions: { [TASKS_EXTENSION]: {} } },
        serverInfo: SERVER_INFO,
      }) };
    case "server/discover":
      // DiscoverResult (/server/discover): supportedVersions + capabilities are
      // the two documented fields, and the method's stated purpose is to let a
      // client learn the server's supported versions and capabilities in one
      // request. HELM-MCP-CONFORM-1: both were absent, and the Tasks extension
      // was advertised as a bare `extensions` array at the result root instead of
      // as the negotiated capabilities.extensions map Tasks' own server guidance
      // shows ("Include the extension in your server/discover capabilities").
      return { status: 200, body: jsonRpcResult(id, {
        resultType: "complete",
        supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
        capabilities: { tools: {}, extensions: { [TASKS_EXTENSION]: {} } },
        instructions: "AINumbers Helm — local control plane. Search the compiled workflow/template catalog, start dry runs or real runs (returned as Tasks; poll tasks/get), and fetch or verify a run's digest-level artifact. evidence.export additionally requires a one-time consent ticket minted by the paired UI.",
      }) };
    case "tools/list":
      return { status: 200, body: jsonRpcResult(id, { resultType: "complete", tools: TOOLS }) };
    case "tools/call": {
      const name = params?.name;
      if (!name) return { status: 200, body: jsonRpcError(id, -32602, "missing_tool_name") };
      if (TASK_RETURNING_TOOLS.has(name) && !declaresTasks(params)) return missingCapability(id, TASKS_EXTENSION);
      try {
        const { resultType, payload, task } = callTool(db, name, params?.arguments || {});
        // Content block types are text | image | audio | resource_link | resource
        // (/server/tools). HELM-MCP-CONFORM-1: helm emitted type "json", which is
        // not among them. Structured data belongs in structuredContent, with the
        // serialized JSON mirrored into a TextContent block for compatibility.
        const result = { resultType };
        if (payload !== undefined) {
          result.content = [{ type: "text", text: JSON.stringify(payload) }];
          result.structuredContent = payload;
        }
        if (task) result.task = task;
        return { status: 200, body: jsonRpcResult(id, result) };
      } catch (err) {
        if (err && typeof err.code === "number") return { status: 200, body: jsonRpcError(id, err.code, err.message) };
        log.error("mcp: tool call failed", { name, error: String(err?.message || err) });
        return { status: 200, body: jsonRpcError(id, -32603, "internal_error") };
      }
    }
    case "tasks/get": {
      // tasks/get exists only under the Tasks extension, so it carries the same
      // capability gate as the tools that mint a task.
      if (!declaresTasks(params)) return missingCapability(id, TASKS_EXTENSION);
      const runId = params?.taskId;
      if (!runId) return { status: 200, body: jsonRpcError(id, -32602, "missing_task_id") };
      const row = runRow(db, runId);
      if (!row) return { status: 200, body: jsonRpcError(id, -32602, "task_not_found") };
      // The poll itself completed — the task's own lifecycle state lives in
      // task.status, not in the result's protocol-level resultType. helm
      // previously surfaced an awaiting_data run as resultType:"input_required",
      // which is the MRTR shape and MUST carry an inputRequests map; helm mints
      // none, so that promised a client a structure that was never present.
      return { status: 200, body: jsonRpcResult(id, {
        resultType: "complete",
        task: { taskId: row.run_id, status: taskStatusFor(row.state), execution_hash: row.execution_hash, ttlMs: TASK_TTL_MS, pollIntervalMs: TASK_POLL_INTERVAL_MS },
      }) };
    }
    default:
      return null; // signals "unknown method" to the caller — HTTP 404 + -32601
  }
}

// Per-request protocol fields live in params._meta, NOT at the body root
// (spec 2026-07-28, Basic §Per-request protocol fields) — same read path
// anchor-suite uses (worker.mjs's requestMeta).
function requestMeta(body) {
  return body?.params?._meta;
}

// A client asserts its version via the MCP-Protocol-Version header (modern) or
// _meta[protocolVersion] (modern); anchor's assertedProtocolVersion, reused verbatim.
function assertedProtocolVersion(protocolVersionHeader, body) {
  return protocolVersionHeader || requestMeta(body)?.[META_PROTOCOL_VERSION] || undefined;
}

// POST /mcp — same Host+Origin+Bearer gate as every other route (already
// applied by the time this handler runs, per server.mjs's dispatch order).
export async function handleMcp(req, res, params, db) {
  if (!db) return sendJson(res, 503, jsonRpcError(null, -32603, "engine_unavailable"));

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, jsonRpcError(null, -32700, "parse_error"));
  }

  if (body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return sendJson(res, 400, jsonRpcError(body.id ?? null, -32600, "invalid_request"));
  }

  const rawProtocolHeader = req.headers["mcp-protocol-version"];
  const protocolVersionHeader = decodeHeaderValue(rawProtocolHeader);
  if (rawProtocolHeader !== undefined && (protocolVersionHeader === null || hasInvalidChar(protocolVersionHeader))) {
    return sendJson(res, 400, jsonRpcError(body.id ?? null, -32022, "unsupported_protocol_version", { supported: SUPPORTED_PROTOCOL_VERSIONS, requested: protocolVersionHeader ?? null }));
  }

  // Version selection (anchor's shipped shape, board/done/MCP728-CONFORM-FIX-1.md):
  // a client may assert its version via the header, _meta, or (on `initialize`
  // only) the legacy params.protocolVersion handshake field. Asserting nothing at
  // all is a legacy request and gets today's permissive behavior — this is the
  // fallback this row exists to add; helm previously required the header on
  // every request unconditionally, which is the defect HELM-MCP-FALLBACK-1 fixes.
  const asserted = assertedProtocolVersion(protocolVersionHeader, body);

  // A header/_meta assertion is a hard requirement (per SEP-2243 / Basic
  // §Per-request protocol fields) — unsupported is -32022 + HTTP 400, unchanged
  // from before this row. It differs from anchor's literal reuse in one respect,
  // stated here rather than invented silently: the legacy `initialize`
  // params.protocolVersion field is advisory under classic (pre-2026) MCP
  // negotiation — "if the server does not support the requested version, it can
  // respond with a different one it does support" — so it does NOT trigger
  // -32022; only an explicit modern assertion does. This matters in practice: a
  // real off-the-shelf @modelcontextprotocol/sdk client's own supported-version
  // list has zero overlap with helm's SUPPORTED_PROTOCOL_VERSIONS above
  // 2025-06-18 (its LATEST_PROTOCOL_VERSION as of SDK 1.29.0 is 2025-11-25, a
  // revision helm never claims to implement), so treating that body field as a
  // hard requirement would fail the exact real-client handshake this row exists
  // to unblock — proven live below.
  if (asserted && !SUPPORTED_PROTOCOL_VERSIONS.includes(asserted)) {
    return sendJson(res, 400, jsonRpcError(body.id ?? null, -32022, "unsupported_protocol_version", { supported: SUPPORTED_PROTOCOL_VERSIONS, requested: asserted }));
  }

  const legacyRequestedVersion = body.method === "initialize" ? body.params?.protocolVersion : undefined;
  const negotiatedVersion = asserted
    || (legacyRequestedVersion && SUPPORTED_PROTOCOL_VERSIONS.includes(legacyRequestedVersion) ? legacyRequestedVersion : undefined)
    // Client named a version we don't implement (or none at all is what an
    // asking-nothing legacy `initialize` gets by staying on our default): if it
    // asked for something specific and unsupported, meet it at our legacy floor
    // rather than our newest — a client naming an older/unrecognized revision is
    // unlikely to understand 2026-07-28 either.
    || (legacyRequestedVersion ? LEGACY_PROTOCOL_VERSION : MCP_PROTOCOL_VERSION);

  // ERA SELECTION — modern iff the client EXPLICITLY asserted 2026-07-28, never
  // by the server default falling through (an unversioned legacy client must
  // stay legacy, not get judged modern and rejected). `initialize` is the
  // legacy opening handshake and stays legacy-era regardless of what it asks
  // for — identical to anchor's modernEra rule.
  const modernEra = body.method !== "initialize" && asserted === MCP_PROTOCOL_VERSION;

  // SEP-2243: Mcp-Method and (on tools/call) Mcp-Name MUST agree with the body
  // when present. Absence is a violation only for a MODERN-era request — a
  // legacy client sends neither header and keeps today's permissive behavior.
  const rawMethodHeader = req.headers["mcp-method"];
  const mcpMethodHeader = decodeHeaderValue(rawMethodHeader);
  const methodHeaderBad = rawMethodHeader === undefined
    ? modernEra
    : (mcpMethodHeader === null || hasInvalidChar(mcpMethodHeader) || mcpMethodHeader !== body.method);
  if (methodHeaderBad) {
    return sendJson(res, 400, jsonRpcError(body.id ?? null, -32020, "HeaderMismatch", { header: "Mcp-Method", requested: body.method ?? null, header_value: mcpMethodHeader ?? null }));
  }
  if (body.method === "tools/call") {
    const rawNameHeader = req.headers["mcp-name"];
    const mcpNameHeader = decodeHeaderValue(rawNameHeader);
    const bodyName = body.params?.name;
    const nameHeaderBad = rawNameHeader === undefined
      ? modernEra
      : (mcpNameHeader === null || hasInvalidChar(mcpNameHeader) || mcpNameHeader !== bodyName);
    if (nameHeaderBad) {
      return sendJson(res, 400, jsonRpcError(body.id ?? null, -32020, "HeaderMismatch", { header: "Mcp-Name", requested: bodyName ?? null, header_value: mcpNameHeader ?? null }));
    }
  }

  // Per-request protocol fields (/basic). 2026-07-28 moved version, identity and
  // capabilities out of a handshake and into every request's _meta:
  // io.modelcontextprotocol/protocolVersion and .../clientCapabilities are
  // REQUIRED on every MODERN-era request (clientInfo is only SHOULD); "A request
  // missing any required field is malformed; the server MUST reject it with
  // JSON-RPC error code -32602 ... 400 Bad Request." Legacy-era requests carry
  // no _meta by definition and are exempt — same era-gating as anchor.
  if (modernEra) {
    const meta = requestMeta(body);
    const missingMeta = [META_PROTOCOL_VERSION, META_CLIENT_CAPABILITIES].filter((k) => meta?.[k] === undefined || meta?.[k] === null);
    if (missingMeta.length) {
      return sendJson(res, 400, jsonRpcError(body.id ?? null, -32602, "missing_required_meta", { missing: missingMeta }));
    }

    // Protocol Version Header (/basic/transports/streamable-http): "The header
    // value MUST match the io.modelcontextprotocol/protocolVersion field carried
    // in the request body's _meta. If the values do not match, the server MUST
    // reject the request with 400 Bad Request and a HeaderMismatch JSON-RPC error."
    if (meta[META_PROTOCOL_VERSION] !== protocolVersionHeader) {
      return sendJson(res, 400, jsonRpcError(body.id ?? null, -32020, "HeaderMismatch", {
        header: "MCP-Protocol-Version",
        requested: meta[META_PROTOCOL_VERSION] ?? null,
        header_value: protocolVersionHeader,
      }));
    }
  }

  const dispatched = dispatch(db, body, negotiatedVersion);
  if (dispatched === null) {
    // Modern-era unknown method is 404 (spec: http §Protocol Version Header);
    // a legacy client keeps its 200, since 2025-06-18 carried no such
    // requirement — anchor's shipped dual-era status split, reused verbatim.
    return sendJson(res, modernEra ? 404 : 200, jsonRpcError(body.id ?? null, -32601, `method_not_found:${body.method}`));
  }
  sendJson(res, dispatched.status, dispatched.body);
}
