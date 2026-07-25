// HELM-HA-1: /ha/pending, /ha/records, /ha/slot, /ha/replay, /run/resume —
// the REST surface the browser (helm.html Review) and any other §27.2
// producer drive against.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-ha-routes-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42101;
const ORIGIN = "null";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { openJournal } = await import("./journal.mjs");
const { createHelmServer } = await import("./server.mjs");
const { executeRun, planSteps } = await import("./run.mjs");
const { pinnedKernelDigest, runKernelNode } = await import("./kernel-runner.mjs");
const { haGateCheckFor } = await import("./ha-gate.mjs");
const { loadOrCreateHaIdentity } = await import("./ha-identity.mjs");
const { sign, rawPubkeyToDidKey } = await import("./vendored/ocg/kernels/_proof.mjs");

const KERNEL_ID = "art-324-tvm-npv";

const config = loadConfig();
const token = loadOrCreateToken();
const db = openJournal(join(TMP, "journal.db"));
let server;
let haIdentity;

before(async () => {
  haIdentity = await loadOrCreateHaIdentity();
  server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, db, haIdentity });
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

function gatedManifest() {
  return {
    manifest_version: "1",
    workflow_id: "wf-ha-routes-test",
    trigger: { type: "manual" },
    connectors: [],
    nodes: [
      { node_id: "n1", kernel_id: KERNEL_ID, kernel_digest: pinnedKernelDigest(KERNEL_ID), policy_parameters: { mode: "periods", discount_rate_pct: 10, cash_flows: [{ amount: -1000, t: 0 }, { amount: 600, t: 1 }, { amount: 600, t: 2 }] } },
      { node_id: "n2", kernel_id: KERNEL_ID, kernel_digest: pinnedKernelDigest(KERNEL_ID), policy_parameters: { mode: "periods", discount_rate_pct: 5, cash_flows: [{ amount: -500, t: 0 }, { amount: 300, t: 1 }] }, gate_policy: "review_required", gate_role: "approver" },
    ],
    gates: [],
    actions: [],
  };
}

async function newIdentity() {
  const keyPair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const id = await rawPubkeyToDidKey(keyPair.publicKey);
  return { id, privateKey: keyPair.privateKey };
}

test("route wiring: a held run surfaces on GET /ha/pending", async () => {
  const manifest = gatedManifest();
  const stepRunner = async (step) => runKernelNode(step, {});
  const held = await executeRun(db, { runId: "route-run-1", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");

  const res = await get("/ha/pending", headers());
  assert.equal(res.status, 200);
  const { pending } = JSON.parse(res.body);
  const mine = pending.find((p) => p.run_id === "route-run-1");
  assert.ok(mine, "held run should appear in /ha/pending");
  assert.equal(mine.step_id, "nodes:n2");
  assert.ok(mine.subjectHash.startsWith("sha256:"));
});

test("route wiring: POST /ha/records accepts a signed approval, GET /ha/records returns it, POST /run/resume completes", async () => {
  const pendingRes = await get("/ha/pending", headers());
  const mine = JSON.parse(pendingRes.body).pending.find((p) => p.run_id === "route-run-1");

  const approver = await newIdentity();
  const unsigned = { record_type: "approval", role: "approver", subject_hash: mine.subjectHash, identity: { id: approver.id }, decision: "approve", timestamp: "2026-07-24T12:00:00Z" };
  const record = await sign(unsigned, { verificationMethod: `${approver.id}#key-1`, created: "2026-07-24T12:00:00Z", privateKey: approver.privateKey });

  const submitRes = await post("/ha/records", { record }, headers());
  assert.equal(submitRes.status, 200);
  assert.equal(JSON.parse(submitRes.body).ok, true);

  const recordsRes = await get(`/ha/records?subject_hash=${encodeURIComponent(mine.subjectHash)}`, headers());
  assert.equal(JSON.parse(recordsRes.body).records.length, 1);

  const resumeRes = await post("/run/resume", { run_id: "route-run-1" }, headers());
  assert.equal(resumeRes.status, 200);
  assert.equal(JSON.parse(resumeRes.body).state, "completed");
});

test("route wiring: POST /ha/records refuses a tampered signature (422)", async () => {
  const approver = await newIdentity();
  const unsigned = { record_type: "approval", role: "approver", subject_hash: "sha256:" + "7".repeat(64), identity: { id: approver.id }, decision: "approve", timestamp: "2026-07-24T12:00:00Z" };
  const record = await sign(unsigned, { verificationMethod: `${approver.id}#key-1`, created: "2026-07-24T12:00:00Z", privateKey: approver.privateKey });
  record.decision = "reject";
  const res = await post("/ha/records", { record }, headers());
  assert.equal(res.status, 422);
});

test("route wiring: POST /ha/replay re-executes the kernel and returns a real replay_verified verdict; GET /ha/slot reflects it", async () => {
  const manifest = gatedManifest();
  const stepRunner = async (step) => runKernelNode(step, {});
  await executeRun(db, { runId: "route-run-replay", manifest, stepRunner });
  const [n1] = planSteps(manifest);

  const res = await post("/ha/replay", { run_id: "route-run-replay", step_id: n1.step_id }, headers());
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.matched, true);

  const slotRes = await get(`/ha/slot?subject_hash=${encodeURIComponent(body.claimedHash)}`, headers());
  const { slot } = JSON.parse(slotRes.body);
  assert.equal(slot.countersignatures[0].replay_verified, true);
});

test("route wiring: POST /run/resume 409s a run that isn't actually held", async () => {
  const manifest = gatedManifest();
  const stepRunner = async (step) => runKernelNode(step, {});
  await executeRun(db, { runId: "route-run-notheld", manifest, stepRunner }); // no gateCheck — completes straight through
  const res = await post("/run/resume", { run_id: "route-run-notheld" }, headers());
  assert.equal(res.status, 409);
});
