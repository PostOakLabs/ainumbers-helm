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
const SUPPORTED_PROTOCOL_VERSIONS = [MCP_PROTOCOL_VERSION];

// SEP-2243 (final): three REQUIRED-for-compliance headers. MCP-Protocol-Version
// and Mcp-Method apply to every request; Mcp-Name additionally applies to
// tools/call (our only method in that named set — resources/read and
// prompts/get aren't implemented here). Missing, mismatched, or invalid-char
// -> -32020 HeaderMismatch + HTTP 400 (Q1, re-confirmed against final text).
const BASE64_SENTINEL = /^=\?base64\?B\?([A-Za-z0-9+/=]+)\?=$/i;

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

function jsonRpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
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

// Every successful tool result carries resultType (spec MUST): "task" for
// the two run-starting tools (Tasks extension — the run continues after
// this response, poll tasks/get), "success" for everything else, which is
// synchronous read-only work against already-persisted state.
function callTool(db, name, args = {}) {
  switch (name) {
    case "catalog.search": {
      const q = (args.query || "").toLowerCase();
      const workflows = listPacks().filter((w) => !q || w.workflow_id.includes(q) || w.name?.toLowerCase().includes(q) || w.outcome?.toLowerCase().includes(q));
      const templates = listTemplates().filter((t) => !q || t.slug.includes(q) || t.title?.toLowerCase().includes(q) || t.blurb?.toLowerCase().includes(q));
      return { resultType: "success", workflows, templates };
    }
    case "workflow.describe": {
      const pack = getPack(args.workflow_id);
      if (!pack) throw { code: -32602, message: "workflow_not_found" };
      return { resultType: "success", workflow_id: pack.workflow_id, name: pack.name, outcome: pack.outcome, manifest_digest: manifestDigest(pack.manifest) };
    }
    case "workflow.manifest_get": {
      const pack = getPack(args.workflow_id);
      if (!pack) throw { code: -32602, message: "workflow_not_found" };
      return { resultType: "success", manifest: pack.manifest };
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
      return { resultType: "task", task: { taskId: started.runId, status: "working" } };
    }
    case "artifact.get": {
      if (!args.run_id) throw { code: -32602, message: "missing_run_id" };
      const row = runRow(db, args.run_id);
      if (!row) throw { code: -32602, message: "run_not_found" };
      return {
        resultType: "success",
        run_id: row.run_id,
        state: row.state,
        execution_hash: row.execution_hash,
        workflow_manifest_digest: row.workflow_manifest_digest,
        steps: stepDigestsFor(db, row.run_id),
      };
    }
    case "artifact.verify": {
      if (!args.run_id) throw { code: -32602, message: "missing_run_id" };
      const row = runRow(db, args.run_id);
      if (!row) throw { code: -32602, message: "run_not_found" };
      if (row.state !== "completed") return { resultType: "success", valid: false, reason: `run_not_completed:${row.state}` };
      let recomputed;
      try {
        recomputed = replayExecutionHash(db, args.run_id);
      } catch (err) {
        return { resultType: "success", valid: false, reason: String(err?.message || err) };
      }
      return { resultType: "success", valid: recomputed === row.execution_hash, execution_hash: row.execution_hash, recomputed };
    }
    case "evidence.export": {
      if (!args.run_id) throw { code: -32602, message: "missing_run_id" };
      if (!args.ticket || !redeemExportTicket(args.ticket)) {
        throw { code: -32602, message: "consent_required — mint a ticket via POST /evidence/export/ticket from the paired UI first" };
      }
      const row = runRow(db, args.run_id);
      if (!row) throw { code: -32602, message: "run_not_found" };
      return {
        resultType: "success",
        trust_label: "hash_verified",
        run_id: row.run_id,
        state: row.state,
        execution_hash: row.execution_hash,
        workflow_manifest_digest: row.workflow_manifest_digest,
        steps: stepDigestsFor(db, row.run_id),
      };
    }
    default:
      throw { code: -32602, message: `unknown_tool:${name}` };
  }
}

function dispatch(db, req_) {
  const { id, method, params } = req_;
  switch (method) {
    case "initialize":
      return jsonRpcResult(id, {
        resultType: "success",
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {}, extensions: { "io.modelcontextprotocol/tasks": {} } },
        serverInfo: { name: "co.ainumbers/helm", version: MCP_PROTOCOL_VERSION },
      });
    case "server/discover":
      return jsonRpcResult(id, { resultType: "success", name: "co.ainumbers/helm", extensions: ["io.modelcontextprotocol/tasks"] });
    case "tools/list":
      return jsonRpcResult(id, { resultType: "success", tools: TOOLS });
    case "tools/call": {
      const name = params?.name;
      if (!name) return jsonRpcError(id, -32602, "missing_tool_name");
      try {
        const result = callTool(db, name, params?.arguments || {});
        return jsonRpcResult(id, { content: [{ type: "json", json: result }], resultType: result.resultType, ...(result.task ? { task: result.task } : {}) });
      } catch (err) {
        if (err && typeof err.code === "number") return jsonRpcError(id, err.code, err.message);
        log.error("mcp: tool call failed", { name, error: String(err?.message || err) });
        return jsonRpcError(id, -32603, "internal_error");
      }
    }
    case "tasks/get": {
      const runId = params?.taskId;
      if (!runId) return jsonRpcError(id, -32602, "missing_task_id");
      const row = runRow(db, runId);
      if (!row) return jsonRpcError(id, -32602, "task_not_found");
      return jsonRpcResult(id, {
        resultType: taskStatusFor(row.state) === "input_required" ? "input_required" : "success",
        task: { taskId: row.run_id, status: taskStatusFor(row.state), execution_hash: row.execution_hash },
      });
    }
    default:
      return null; // signals "unknown method" to the caller — HTTP 404 + -32601
  }
}

// POST /mcp — same Host+Origin+Bearer gate as every other route (already
// applied by the time this handler runs, per server.mjs's dispatch order).
export async function handleMcp(req, res, params, db) {
  if (!db) return sendJson(res, 503, jsonRpcError(null, -32603, "engine_unavailable"));

  const protocolVersionHeader = decodeHeaderValue(req.headers["mcp-protocol-version"]);
  if (!protocolVersionHeader || hasInvalidChar(protocolVersionHeader) || !SUPPORTED_PROTOCOL_VERSIONS.includes(protocolVersionHeader)) {
    return sendJson(res, 400, jsonRpcError(null, -32022, "unsupported_protocol_version", { supported: SUPPORTED_PROTOCOL_VERSIONS, requested: protocolVersionHeader ?? null }));
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch {
    return sendJson(res, 400, jsonRpcError(null, -32700, "parse_error"));
  }

  const mcpMethodHeader = decodeHeaderValue(req.headers["mcp-method"]);
  if (!mcpMethodHeader || hasInvalidChar(mcpMethodHeader) || mcpMethodHeader !== body.method) {
    return sendJson(res, 400, jsonRpcError(body.id ?? null, -32020, "HeaderMismatch", { header: "Mcp-Method", requested: body.method ?? null, header_value: mcpMethodHeader ?? null }));
  }
  if (body.method === "tools/call") {
    const mcpNameHeader = decodeHeaderValue(req.headers["mcp-name"]);
    const bodyName = body.params?.name;
    if (!mcpNameHeader || hasInvalidChar(mcpNameHeader) || mcpNameHeader !== bodyName) {
      return sendJson(res, 400, jsonRpcError(body.id ?? null, -32020, "HeaderMismatch", { header: "Mcp-Name", requested: bodyName ?? null, header_value: mcpNameHeader ?? null }));
    }
  }

  if (body.jsonrpc !== "2.0" || typeof body.method !== "string") {
    return sendJson(res, 400, jsonRpcError(body.id ?? null, -32600, "invalid_request"));
  }

  const result = dispatch(db, body);
  if (result === null) {
    return sendJson(res, 404, jsonRpcError(body.id ?? null, -32601, `method_not_found:${body.method}`));
  }
  sendJson(res, 200, result);
}
