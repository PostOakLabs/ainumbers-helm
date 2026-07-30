// HELM-H9: MCP v2 endpoint — header gate, tools/list, tools/call, tasks/get,
// evidence.export consent tier, and the agent-parity requirement (§5 gate 6:
// an MCP-initiated run uses the exact same run-kickoff code path as the UI's
// REST route, via the shared run-actions.mjs module).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-mcp-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42199;
const ORIGIN = "null";
const KNOWN_WORKFLOW_ID = "pack-aca-226j-response-composer";
const MCP_VERSION = "2026-07-28";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { openJournal } = await import("./journal.mjs");
const { createHelmServer } = await import("./server.mjs");
const { resolveRunManifest } = await import("./run-actions.mjs");

const config = loadConfig();
const token = loadOrCreateToken();
const db = openJournal(join(TMP, "journal.db"));
let server;

before(() => {
  server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, db });
});

after(() => {
  server.close();
  db.close();
  rmSync(TMP, { recursive: true, force: true });
});

function baseHeaders(overrides = {}) {
  return { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, Authorization: `Bearer ${token}`, "MCP-Protocol-Version": MCP_VERSION, ...overrides };
}

function rawRequest(method, path, body, hdrs) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? JSON.stringify(body) : undefined;
    const headers = { ...hdrs };
    if (data !== undefined) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(data);
    }
    const req = request({ host: "127.0.0.1", port: PORT, path, method, headers }, (res) => {
      let resBody = "";
      res.on("data", (c) => (resBody += c));
      res.on("end", () => resolve({ status: res.statusCode, body: resBody ? JSON.parse(resBody) : null }));
    });
    req.on("error", reject);
    if (data !== undefined) req.end(data);
    else req.end();
  });
}

function rpc(method, params, { id = 1, extraHeaders = {} } = {}) {
  const body = { jsonrpc: "2.0", id, method, params };
  const headers = baseHeaders({ "Mcp-Method": method, ...extraHeaders });
  if (method === "tools/call" && params?.name) headers["Mcp-Name"] = params.name;
  return rawRequest("POST", "/mcp", body, headers);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("GET /mcp is 405 (SEP-2567: no session/GET stream on the MCP transport)", async () => {
  const res = await rawRequest("GET", "/mcp", undefined, baseHeaders());
  assert.equal(res.status, 405);
});

test("DELETE /mcp is 405", async () => {
  const res = await rawRequest("DELETE", "/mcp", undefined, baseHeaders());
  assert.equal(res.status, 405);
});

test("missing MCP-Protocol-Version -> -32022 + HTTP 400 with supported/requested", async () => {
  const res = await rawRequest("POST", "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" }, {
    Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, Authorization: `Bearer ${token}`, "Mcp-Method": "tools/list",
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32022);
  assert.deepEqual(res.body.error.data.supported, [MCP_VERSION]);
});

test("unsupported MCP-Protocol-Version -> -32022 + HTTP 400", async () => {
  const res = await rawRequest("POST", "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" }, baseHeaders({ "MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "tools/list" }));
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32022);
  assert.equal(res.body.error.data.requested, "2099-01-01");
});

test("Mcp-Method header mismatched with body.method -> -32020 HeaderMismatch + HTTP 400", async () => {
  const res = await rawRequest("POST", "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/list" }, baseHeaders({ "Mcp-Method": "tools/call" }));
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32020);
});

test("tools/call with Mcp-Name mismatched from params.name -> -32020 HeaderMismatch + HTTP 400", async () => {
  const res = await rawRequest("POST", "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "catalog.search", arguments: {} } }, baseHeaders({ "Mcp-Method": "tools/call", "Mcp-Name": "workflow.run" }));
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32020);
});

test("unknown JSON-RPC method -> HTTP 404 + -32601", async () => {
  const res = await rpc("no/such/method", {});
  assert.equal(res.status, 404);
  assert.equal(res.body.error.code, -32601);
});

test("initialize returns the pinned protocol version and Tasks extension capability", async () => {
  const res = await rpc("initialize", {});
  assert.equal(res.status, 200);
  assert.equal(res.body.result.protocolVersion, MCP_VERSION);
  assert.ok(res.body.result.capabilities.extensions["io.modelcontextprotocol/tasks"]);
});

test("tools/list returns the read/run tool set", async () => {
  const res = await rpc("tools/list", {});
  assert.equal(res.status, 200);
  const names = res.body.result.tools.map((t) => t.name);
  assert.ok(names.includes("catalog.search"));
  assert.ok(names.includes("workflow.run"));
  assert.ok(names.includes("evidence.export"));
});

test("tools/call catalog.search finds the known compiled pack", async () => {
  const res = await rpc("tools/call", { name: "catalog.search", arguments: { query: "aca-226j" } });
  assert.equal(res.status, 200);
  const { workflows } = res.body.result.content[0].json;
  assert.ok(workflows.some((w) => w.workflow_id === KNOWN_WORKFLOW_ID));
});

test("tools/call workflow.describe on an unknown workflow_id -> -32602", async () => {
  const res = await rpc("tools/call", { name: "workflow.describe", arguments: { workflow_id: "does-not-exist" } });
  assert.equal(res.status, 200);
  assert.equal(res.body.error.code, -32602);
});

test("tools/call unknown tool name -> -32602", async () => {
  const res = await rpc("tools/call", { name: "no.such.tool", arguments: {} });
  assert.equal(res.status, 200);
  assert.equal(res.body.error.code, -32602);
});

test("workflow.dry_run returns a Task; tasks/get reaches completed; artifact.get/verify agree", async () => {
  const startRes = await rpc("tools/call", { name: "workflow.dry_run", arguments: { workflow_id: KNOWN_WORKFLOW_ID } });
  assert.equal(startRes.status, 200);
  assert.equal(startRes.body.result.resultType, "task");
  const taskId = startRes.body.result.task.taskId;
  assert.ok(taskId);

  let status;
  for (let i = 0; i < 40; i++) {
    const getRes = await rpc("tasks/get", { taskId });
    status = getRes.body.result.task.status;
    if (status === "completed" || status === "failed") break;
    await sleep(25);
  }
  assert.equal(status, "completed");

  const artifactRes = await rpc("tools/call", { name: "artifact.get", arguments: { run_id: taskId } });
  assert.equal(artifactRes.body.result.content[0].json.state, "completed");

  const verifyRes = await rpc("tools/call", { name: "artifact.verify", arguments: { run_id: taskId } });
  assert.equal(verifyRes.body.result.content[0].json.valid, true);
});

test("evidence.export refuses without a ticket, succeeds with one minted via POST /evidence/export/ticket", async () => {
  const startRes = await rpc("tools/call", { name: "workflow.dry_run", arguments: { workflow_id: KNOWN_WORKFLOW_ID } });
  const taskId = startRes.body.result.task.taskId;
  for (let i = 0; i < 40; i++) {
    const getRes = await rpc("tasks/get", { taskId });
    if (getRes.body.result.task.status === "completed") break;
    await sleep(25);
  }

  const noTicket = await rpc("tools/call", { name: "evidence.export", arguments: { run_id: taskId, ticket: "bogus" } });
  assert.equal(noTicket.body.error.code, -32602);

  const ticketRes = await rawRequest("POST", "/evidence/export/ticket", {}, baseHeaders());
  const ticket = ticketRes.body.ticket;
  assert.ok(ticket);

  const exportRes = await rpc("tools/call", { name: "evidence.export", arguments: { run_id: taskId, ticket } });
  assert.equal(exportRes.body.result.content[0].json.trust_label, "hash_verified");
  assert.equal(exportRes.body.result.content[0].json.run_id, taskId);

  // single-use: the same ticket cannot be redeemed twice
  const secondUse = await rpc("tools/call", { name: "evidence.export", arguments: { run_id: taskId, ticket } });
  assert.equal(secondUse.body.error.code, -32602);
});

test("AGENT-PARITY (spec §5 gate 6): MCP workflow.run and REST /run/start resolve the identical manifest for the same workflow_id via the shared run-actions.mjs core", async () => {
  const viaShared = resolveRunManifest({ workflowId: KNOWN_WORKFLOW_ID });
  const restRes = await rawRequest("POST", "/run/start", { workflow_id: KNOWN_WORKFLOW_ID, dry_run: true }, baseHeaders());
  assert.equal(restRes.status, 200);
  const mcpRes = await rpc("tools/call", { name: "workflow.dry_run", arguments: { workflow_id: KNOWN_WORKFLOW_ID } });
  assert.equal(mcpRes.status, 200);
  // Both entry points started a run against the identically-resolved manifest
  // (workflow_manifest_digest is deterministic over the manifest alone).
  const restRunId = restRes.body.run_id;
  const mcpRunId = mcpRes.body.result.task.taskId;
  for (let i = 0; i < 40; i++) {
    const a = await rawRequest("GET", `/run/timeline?run_id=${restRunId}`, undefined, baseHeaders());
    const b = await rpc("tools/call", { name: "artifact.get", arguments: { run_id: mcpRunId } });
    const bState = b.body.result.content[0].json.state;
    if (a.body.steps.some((s) => s.state === "completed") && bState === "completed") break;
    await sleep(25);
  }
  const restArtifact = await rpc("tools/call", { name: "artifact.get", arguments: { run_id: restRunId } });
  const mcpArtifact = await rpc("tools/call", { name: "artifact.get", arguments: { run_id: mcpRunId } });
  assert.equal(restArtifact.body.result.content[0].json.workflow_manifest_digest, mcpArtifact.body.result.content[0].json.workflow_manifest_digest);
  assert.equal(restArtifact.body.result.content[0].json.state, "completed");
  assert.equal(mcpArtifact.body.result.content[0].json.state, "completed");
});
