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

const META_VERSION = "io.modelcontextprotocol/protocolVersion";
const META_CAPS = "io.modelcontextprotocol/clientCapabilities";
const TASKS_EXT = "io.modelcontextprotocol/tasks";

// Per-request protocol fields are REQUIRED on every 2026-07-28 request. The
// default client here declares the Tasks extension; `capabilities` overrides it
// so a test can act as a client that never declared support.
function requestMeta(capabilities) {
  return {
    [META_VERSION]: MCP_VERSION,
    "io.modelcontextprotocol/clientInfo": { name: "helm-mcp-test", version: "1.0.0" },
    [META_CAPS]: capabilities ?? { extensions: { [TASKS_EXT]: {} } },
  };
}

function rpc(method, params, { id = 1, extraHeaders = {}, capabilities, meta } = {}) {
  const _meta = meta === null ? undefined : meta ?? requestMeta(capabilities);
  const body = { jsonrpc: "2.0", id, method, params: { ...params, ...(_meta ? { _meta } : {}) } };
  // Mcp-Name defaults to params.name, but an explicit extraHeaders value wins —
  // the sentinel tests depend on being able to send a *different* encoding of it.
  const defaults = method === "tools/call" && params?.name ? { "Mcp-Name": params.name } : {};
  const headers = baseHeaders({ "Mcp-Method": method, ...defaults, ...extraHeaders });
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

// ---------------------------------------------------------------------------
// HELM-MCP-CONFORM-1 (2026-07-30) — the six defects from
// research/MCP-CONFORMANCE-AUDIT-1-2026-07-30.md, each pinned by a test.
// ---------------------------------------------------------------------------

test("CONFORM-1: Mcp-Name accepts the SPEC base64 sentinel =?base64?<b64>?=", async () => {
  // Transports/Value Encoding: `Mcp-Name: =?base64?{Base64EncodedValue}?=`.
  const encoded = `=?base64?${Buffer.from("catalog.search", "utf8").toString("base64")}?=`;
  const res = await rpc("tools/call", { name: "catalog.search", arguments: { query: "aca-226j" } }, { extraHeaders: { "Mcp-Name": encoded } });
  assert.equal(res.status, 200);
  assert.equal(res.body.result.resultType, "complete");
});

test("CONFORM-1: the legacy non-spec =?base64?B?<b64>?= form is REJECTED", async () => {
  // Deliberate: no emitter of the `B?` form exists anywhere in the repo outside
  // this endpoint's own source, and a second accepted encoding is a second canon.
  // The `B?` string is not a valid sentinel, so it is compared literally against
  // the body value and fails as an ordinary header mismatch.
  const legacy = `=?base64?B?${Buffer.from("catalog.search", "utf8").toString("base64")}?=`;
  const res = await rpc("tools/call", { name: "catalog.search", arguments: {} }, { extraHeaders: { "Mcp-Name": legacy } });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32020);
});

test("CONFORM-1: the sentinel markers are case-SENSITIVE (=?BASE64? is not a sentinel)", async () => {
  const upper = `=?BASE64?${Buffer.from("catalog.search", "utf8").toString("base64")}?=`;
  const res = await rpc("tools/call", { name: "catalog.search", arguments: {} }, { extraHeaders: { "Mcp-Name": upper } });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32020);
});

test("CONFORM-2: resultType is drawn from the DEFINED set — never the undefined value 'success'", async () => {
  const defined = new Set(["complete", "input_required", "task"]);
  for (const [method, params] of [["initialize", {}], ["server/discover", {}], ["tools/list", {}], ["tools/call", { name: "catalog.search", arguments: {} }]]) {
    const res = await rpc(method, params);
    assert.equal(res.status, 200, method);
    assert.ok(defined.has(res.body.result.resultType), `${method} returned resultType ${JSON.stringify(res.body.result.resultType)}`);
  }
});

test("CONFORM-3: server/discover returns supportedVersions + capabilities (a real DiscoverResult)", async () => {
  const res = await rpc("server/discover", {});
  assert.equal(res.status, 200);
  assert.equal(res.body.result.resultType, "complete");
  assert.deepEqual(res.body.result.supportedVersions, [MCP_VERSION]);
  assert.ok(res.body.result.capabilities.tools);
  // Tasks: "Include the extension in your server/discover capabilities" — as a
  // map under capabilities.extensions, not a bare array at the result root.
  assert.ok(res.body.result.capabilities.extensions[TASKS_EXT]);
  assert.equal(res.body.result.extensions, undefined);
  assert.equal(res.body.result._meta["io.modelcontextprotocol/serverInfo"].name, "co.ainumbers/helm");
});

test("CONFORM-4: a Tasks result is NOT returned to a client that did not declare the extension", async () => {
  const res = await rpc("tools/call", { name: "workflow.dry_run", arguments: { workflow_id: KNOWN_WORKFLOW_ID } }, { capabilities: {} });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32021);
  assert.ok(res.body.error.data.requiredCapabilities.extensions[TASKS_EXT]);
});

test("CONFORM-4: tasks/get is gated on the same declared capability", async () => {
  const res = await rpc("tasks/get", { taskId: "whatever" }, { capabilities: { extensions: {} } });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32021);
});

test("CONFORM-6: a request with no _meta at all -> -32602 + HTTP 400", async () => {
  const res = await rpc("tools/list", {}, { meta: null });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32602);
});

test("CONFORM-6: _meta missing clientCapabilities -> -32602 + HTTP 400", async () => {
  const res = await rpc("tools/list", {}, { meta: { [META_VERSION]: MCP_VERSION } });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32602);
  assert.deepEqual(res.body.error.data.missing, [META_CAPS]);
});

test("CONFORM-6: _meta protocolVersion not matching the header -> -32020 HeaderMismatch + HTTP 400", async () => {
  const res = await rpc("tools/list", {}, { meta: { ...requestMeta(), [META_VERSION]: "2025-06-18" } });
  assert.equal(res.status, 400);
  assert.equal(res.body.error.code, -32020);
  assert.equal(res.body.error.data.header, "MCP-Protocol-Version");
});

test("CONFORM: unknown method is STILL HTTP 404 (the one thing helm already got right)", async () => {
  const res = await rpc("resources/read", { uri: "file:///nope" });
  assert.equal(res.status, 404);
  assert.equal(res.body.error.code, -32601);
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
  const { workflows } = res.body.result.structuredContent;
  assert.ok(workflows.some((w) => w.workflow_id === KNOWN_WORKFLOW_ID));
  // Content block types are text|image|audio|resource_link|resource — "json" is
  // not among them; the serialized payload is mirrored into a TextContent block.
  assert.equal(res.body.result.content[0].type, "text");
  assert.deepEqual(JSON.parse(res.body.result.content[0].text), res.body.result.structuredContent);
  assert.equal(res.body.result.resultType, "complete");
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
  assert.equal(artifactRes.body.result.structuredContent.state, "completed");

  const verifyRes = await rpc("tools/call", { name: "artifact.verify", arguments: { run_id: taskId } });
  assert.equal(verifyRes.body.result.structuredContent.valid, true);
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
  assert.equal(exportRes.body.result.structuredContent.trust_label, "hash_verified");
  assert.equal(exportRes.body.result.structuredContent.run_id, taskId);

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
    const bState = b.body.result.structuredContent.state;
    if (a.body.steps.some((s) => s.state === "completed") && bState === "completed") break;
    await sleep(25);
  }
  const restArtifact = await rpc("tools/call", { name: "artifact.get", arguments: { run_id: restRunId } });
  const mcpArtifact = await rpc("tools/call", { name: "artifact.get", arguments: { run_id: mcpRunId } });
  assert.equal(restArtifact.body.result.structuredContent.workflow_manifest_digest, mcpArtifact.body.result.structuredContent.workflow_manifest_digest);
  assert.equal(restArtifact.body.result.structuredContent.state, "completed");
  assert.equal(mcpArtifact.body.result.structuredContent.state, "completed");
});
