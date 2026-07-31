// HELM-P2-U4: Choose/Canvas/Run wiring — /workflows, /workflow-manifest,
// /run/start + /run/timeline, and the /events run_id progress stream.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-run-routes-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42099;
const ORIGIN = "null";
const KNOWN_WORKFLOW_ID = "pack-aca-226j-response-composer";

// HELM-BIND-0: node n1 of this pack pins art-01-ap2-mandate-chain-validator,
// whose compute() throws on {} (intent/payment/validate_at required) —
// exactly the "kernel a real number must reach" case. n2-n4 tolerate {}, so
// the whole run still reaches "completed" once n1's real input is supplied.
const BIND_WORKFLOW_ID = "pack-agent-commerce-conformance";
const AP2_FIXTURES = JSON.parse(
  readFileSync(join(import.meta.dirname, "vendored/ocg/kernels/fixtures/art-01-ap2-mandate-chain-validator.fixtures.json"), "utf8")
).vectors;
const AP2_INPUT_A = AP2_FIXTURES.find((v) => v.name === "valid_trio_pass").policy_parameters;
const AP2_INPUT_B = AP2_FIXTURES.find((v) => v.name === "overspend_fail").policy_parameters;

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { openJournal } = await import("./journal.mjs");
const { createHelmServer, getRunsInFlightCount } = await import("./server.mjs");

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

test("§18.2: getRunsInFlightCount returns to 0 once a run finishes (never leaks)", async () => {
  assert.equal(getRunsInFlightCount(), 0, "no run in flight before this test starts one");
  // handleRunStart's executeRun() is fire-and-forget: a dry run over trivial
  // kernel steps can finish within the same microtask turn the HTTP response
  // is written on, so asserting a transient >0 here would be a coin flip.
  // The invariant that matters — never stuck above 0 — is what this checks.
  await post("/run/start", { workflow_id: KNOWN_WORKFLOW_ID, dry_run: true }, headers());
  for (let i = 0; i < 20 && getRunsInFlightCount() > 0; i++) {
    await sleep(25);
  }
  assert.equal(getRunsInFlightCount(), 0, "count must return to 0 once the run finishes");
});

test("GET /events?run_id=...&ticket=... streams progress for a live run (HELM-UX-1 §7.4 ticket, not the bearer, in the query string)", async () => {
  const startRes = await post("/run/start", { workflow_id: KNOWN_WORKFLOW_ID, dry_run: true }, headers());
  const { run_id: runId } = JSON.parse(startRes.body);

  const minted = await post("/events/ticket", {}, headers());
  const { ticket } = JSON.parse(minted.body);

  const events = await new Promise((resolve, reject) => {
    const req = request({
      host: "127.0.0.1",
      port: PORT,
      path: `/events?run_id=${runId}&ticket=${ticket}`,
      method: "GET",
      headers: { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN }, // no Authorization header — proves the ticket path
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

// HELM-BIND-0: closes the §0 finding — no shipped path put real data into a
// kernel node's policy_parameters, so every run computed on {}. These tests
// prove: a caller-supplied number reaches buildArtifact and moves
// execution_hash; invalid supplied inputs are rejected before the run leaves
// `validated`; a run started without required data holds `awaiting_data`
// (the existing, previously-unused, lifecycle state) instead of failing; and
// two runs on different inputs get different input_digests with no shared
// memo row (the §0.4 memoization trap this WU exists to close).

function waitForRunState(runId, predicate, tries = 40) {
  return (async () => {
    for (let i = 0; i < tries; i++) {
      const res = await get(`/run/timeline?run_id=${runId}`, headers());
      const states = JSON.parse(res.body).steps.map((s) => s.state);
      if (predicate(states)) return states;
      await sleep(25);
    }
    throw new Error("timed out waiting for run state");
  })();
}

test("HELM-BIND-0 §1.2: POST /run/start rejects invalid supplied inputs before the run leaves validated", async () => {
  const before = db.prepare("SELECT COUNT(*) AS n FROM runs").get().n;
  const res = await post(
    "/run/start",
    { workflow_id: BIND_WORKFLOW_ID, inputs: { n1: { intent: { mandate_type: "intent" } } } }, // missing payment/validate_at
    headers()
  );
  assert.equal(res.status, 400);
  assert.equal(JSON.parse(res.body).error, "invalid_inputs");
  // rejected before a run row is ever inserted — never even reaches `validated`.
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM runs").get().n, before);
});

test("HELM-BIND-0 §1.4: a run started without n1's required data holds awaiting_data, not failed", async () => {
  const startRes = await post("/run/start", { workflow_id: BIND_WORKFLOW_ID }, headers());
  const { run_id: runId } = JSON.parse(startRes.body);
  const states = await waitForRunState(runId, (s) => s.includes("awaiting_data"));
  assert.ok(states.includes("awaiting_data"), `expected awaiting_data, got: ${states.join(",")}`);
  assert.ok(!states.includes("failed"), `must not fail outright, got: ${states.join(",")}`);
  assert.ok(!states.includes("completed"), `must not complete without n1's data, got: ${states.join(",")}`);
});

test("HELM-BIND-0 §1.1/§1.3: a real supplied number reaches buildArtifact, changes execution_hash, and is recoverable from the persisted step result", async () => {
  const startRes = await post("/run/start", { workflow_id: BIND_WORKFLOW_ID, inputs: { n1: AP2_INPUT_A } }, headers());
  const { run_id: runId } = JSON.parse(startRes.body);
  await waitForRunState(runId, (s) => s.includes("completed"));

  const run = db.prepare("SELECT execution_hash FROM runs WHERE run_id = ?").get(runId);
  assert.ok(run.execution_hash?.startsWith("sha256:"));

  const stepRow = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = 'nodes:n1'").get(runId);
  assert.ok(stepRow, "n1's step result must be persisted");
  const output = JSON.parse(stepRow.output_json);
  // the exact supplied value, recoverable from what the run persisted — a
  // verifier reading this row sees precisely what the computation consumed.
  assert.deepEqual(output.artifact.policy_parameters, AP2_INPUT_A);
});

test("HELM-BIND-0 §0.4: two runs of the same pack with DIFFERENT n1 inputs get different input_digests, no shared memo row, and different execution_hashes", async () => {
  const startA = await post("/run/start", { workflow_id: BIND_WORKFLOW_ID, inputs: { n1: AP2_INPUT_A } }, headers());
  const { run_id: runIdA } = JSON.parse(startA.body);
  await waitForRunState(runIdA, (s) => s.includes("completed"));

  const startB = await post("/run/start", { workflow_id: BIND_WORKFLOW_ID, inputs: { n1: AP2_INPUT_B } }, headers());
  const { run_id: runIdB } = JSON.parse(startB.body);
  await waitForRunState(runIdB, (s) => s.includes("completed"));

  const stepA = db.prepare("SELECT input_digest FROM step_results WHERE run_id = ? AND step_id = 'nodes:n1'").get(runIdA);
  const stepB = db.prepare("SELECT input_digest FROM step_results WHERE run_id = ? AND step_id = 'nodes:n1'").get(runIdB);
  assert.notEqual(stepA.input_digest, stepB.input_digest, "different inputs must not collide in the memo table");

  const shared = db.prepare("SELECT COUNT(*) AS n FROM step_results WHERE step_id = 'nodes:n1' AND input_digest = ? AND run_id != ?").get(stepA.input_digest, runIdA);
  assert.equal(shared.n, 0, "run A's input_digest must not appear under any other run_id");

  const runA = db.prepare("SELECT execution_hash FROM runs WHERE run_id = ?").get(runIdA);
  const runB = db.prepare("SELECT execution_hash FROM runs WHERE run_id = ?").get(runIdB);
  assert.notEqual(runA.execution_hash, runB.execution_hash);
});
