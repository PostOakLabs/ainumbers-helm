// HELM-P2-U4: Choose/Canvas/Run wiring — /workflows, /workflow-manifest,
// /run/start + /run/timeline, and the /events run_id progress stream.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-run-routes-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42099;
const ORIGIN = "null";
const KNOWN_WORKFLOW_ID = "pack-aca-226j-response-composer";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { openJournal } = await import("./journal.mjs");
const { createHelmServer } = await import("./server.mjs");

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

function headers(overrides = {}) {
  return { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, Authorization: `Bearer ${token}`, ...overrides };
}

function get(path, hdrs) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path, method: "GET", headers: hdrs }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function post(path, body, hdrs) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = request(
      { host: "127.0.0.1", port: PORT, path, method: "POST", headers: { ...hdrs, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } },
      (res) => {
        let resBody = "";
        res.on("data", (c) => (resBody += c));
        res.on("end", () => resolve({ status: res.statusCode, body: resBody }));
      }
    );
    req.on("error", reject);
    req.end(data);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("GET /workflows lists the compiled catalog", async () => {
  const res = await get("/workflows", headers());
  assert.equal(res.status, 200);
  const { workflows } = JSON.parse(res.body);
  assert.ok(workflows.length > 0);
  assert.ok(workflows.some((w) => w.workflow_id === KNOWN_WORKFLOW_ID));
  const known = workflows.find((w) => w.workflow_id === KNOWN_WORKFLOW_ID);
  assert.ok(known.name);
  assert.ok(known.outcome);
});

test("GET /workflow-manifest returns the pack's manifest, keyed by workflow_id", async () => {
  const res = await get(`/workflow-manifest?workflow_id=${KNOWN_WORKFLOW_ID}`, headers());
  assert.equal(res.status, 200);
  const manifest = JSON.parse(res.body);
  assert.equal(manifest.workflow_id, KNOWN_WORKFLOW_ID);
  assert.ok(Array.isArray(manifest.nodes) && manifest.nodes.length > 0);
});

test("GET /workflow-manifest 404s for an unknown workflow_id", async () => {
  const res = await get("/workflow-manifest?workflow_id=does-not-exist", headers());
  assert.equal(res.status, 404);
});

test("GET /run/timeline with no run_id returns an empty timeline, not an error", async () => {
  const res = await get("/run/timeline", headers());
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { steps: [] });
});

test("POST /run/start (dry-run) drives the compiled pack end to end; timeline reaches completed", async () => {
  const startRes = await post("/run/start", { workflow_id: KNOWN_WORKFLOW_ID, dry_run: true }, headers());
  assert.equal(startRes.status, 200);
  const { run_id: runId, state } = JSON.parse(startRes.body);
  assert.ok(runId);
  assert.equal(state, "queued");

  let steps = [];
  for (let i = 0; i < 20; i++) {
    const timelineRes = await get(`/run/timeline?run_id=${runId}`, headers());
    steps = JSON.parse(timelineRes.body).steps;
    if (steps.some((s) => s.state === "completed")) break;
    await sleep(25);
  }
  const states = steps.map((s) => s.state);
  assert.ok(states.includes("completed"), `expected a completed transition, got: ${states.join(",")}`);
  assert.ok(states.includes("queued") && states.includes("running"));
});

test("POST /run/start 404s for an unknown workflow_id", async () => {
  const res = await post("/run/start", { workflow_id: "does-not-exist" }, headers());
  assert.equal(res.status, 404);
});

test("GET /events?run_id=...&token=... streams progress for a live run (query-token SSE exception)", async () => {
  const startRes = await post("/run/start", { workflow_id: KNOWN_WORKFLOW_ID, dry_run: true }, headers());
  const { run_id: runId } = JSON.parse(startRes.body);

  const events = await new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port: PORT,
      path: `/events?run_id=${runId}&token=${encodeURIComponent(token)}`,
      method: "GET",
      headers: { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN }, // no Authorization header — proves the query-token path
    });
    let buf = "";
    const seen = [];
    req.on("response", (res) => {
      assert.equal(res.statusCode, 200);
      res.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        let idx;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          const frame = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          seen.push(frame);
          if (frame.includes("event: progress") && frame.includes('"completed"')) {
            req.destroy();
            resolve(seen);
            return;
          }
        }
      });
    });
    req.on("error", (err) => {
      if (seen.length) resolve(seen); // destroy() triggers a benign socket error after we've already resolved
      else reject(err);
    });
    req.end();
    setTimeout(() => reject(new Error("timed out waiting for a completed progress event")), 3000);
  });

  assert.ok(events.some((e) => e.includes("event: ready")));
  assert.ok(events.some((e) => e.includes("event: progress")));
});
