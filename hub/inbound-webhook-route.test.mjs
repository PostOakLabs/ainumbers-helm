// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-INBOUND-WEBHOOK-1: route-level regression tests for the three
// preconditions phil named explicitly (research/PERSONA-phil-2026-07-26.md
// Option 4) — (a) replay rejection, (b) HMAC-before-allowlist with a
// distinct auth-failure signal, (c) deny-by-default run-resume that survives
// even an explicit contract grant (gate re-verified, never bypassed).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";
import { createHmac, randomUUID } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-inbound-webhook-route-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42151;
const ORIGIN = "null";
const SECRET = "test-shared-secret-do-not-use-in-prod";
const SECRET_REF = "vault://helm/connectors/inbound-webhook/shared-secret";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { openJournal } = await import("./journal.mjs");
const { createHelmServer } = await import("./server.mjs");
const { vaultSet } = await import("./vault.mjs");
const { executeRun, planSteps } = await import("./run.mjs");
const { pinnedKernelDigest, runKernelNode } = await import("./kernel-runner.mjs");
const { haGateCheckFor } = await import("./ha-gate.mjs");
const { __resetNonceStoreForTest, __resetIdempotencyStoreForTest } = await import("./webhook-guard.mjs");

const KERNEL_ID = "art-324-tvm-npv";
const RESUME_GRANTED_CONTRACT_PATH = join(TMP, "inbound-webhook.resume-granted.contract.json");

writeFileSync(
  RESUME_GRANTED_CONTRACT_PATH,
  JSON.stringify({
    connector_id: "inbound-webhook",
    connector_version: "1.0.0",
    publisher: "ainumbers-helm",
    allowed_hosts: ["hooks.n8n.example", "hooks.zapier.example"],
    allowed_methods: ["POST"],
    scopes: ["governed-step.receive", "run.resume"],
    vault_scope: [SECRET_REF],
  })
);

vaultSet(SECRET_REF, SECRET);

const config = loadConfig();
const token = loadOrCreateToken();
const db = openJournal(join(TMP, "journal.db"));
let serverDefault; // default contract — no run.resume grant
let serverResumeGranted; // grants run.resume

before(async () => {
  serverDefault = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, db });
  serverResumeGranted = createHelmServer({
    port: config.port + 1,
    allowedOrigin: config.allowedOrigin,
    token,
    db,
    inboundWebhookContractPath: RESUME_GRANTED_CONTRACT_PATH,
  });
});

after(() => {
  serverDefault.close();
  serverResumeGranted.close();
  db.close();
  rmSync(TMP, { recursive: true, force: true });
});

function sign(rawBody) {
  return "sha256=" + createHmac("sha256", SECRET).update(rawBody).digest("hex");
}

function postWebhook(port, payload, { signature, host } = {}) {
  const raw = Buffer.from(JSON.stringify(payload), "utf8");
  const sig = signature !== undefined ? signature : sign(raw);
  return new Promise((resolve, reject) => {
    const headers = {
      Host: host ?? `127.0.0.1:${port}`,
      "Content-Type": "application/json",
      "Content-Length": raw.length,
    };
    if (sig !== null) headers["X-Helm-Webhook-Signature"] = sig;
    const req = request({ host: "127.0.0.1", port, path: "/connectors/inbound-webhook", method: "POST", headers }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, body: body ? JSON.parse(body) : null }));
    });
    req.on("error", reject);
    req.end(raw);
  });
}

function basePayload(overrides = {}) {
  return {
    sourceHost: "hooks.n8n.example",
    method: "POST",
    runId: "run-1",
    workflowManifestDigest: "sha256:" + "a".repeat(64),
    timestamp: new Date().toISOString(),
    nonce: randomUUID(),
    idempotencyKey: randomUUID(),
    data: { step: "reconcile", status: "done" },
    ...overrides,
  };
}

function egressRows(decision) {
  return db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:inbound-webhook")
    .map((r) => JSON.parse(r.entry_json))
    .filter((e) => e.decision === decision);
}

test("inbound-webhook route: valid signed request is accepted and attested", async () => {
  __resetNonceStoreForTest();
  __resetIdempotencyStoreForTest();
  const res = await postWebhook(PORT, basePayload());
  assert.equal(res.status, 200);
  assert.equal(res.body.attestation.connector_id, "inbound-webhook");
  assert.equal(res.body.resumeAuthorized, false);
});

test("(a) a replayed identical body+signature is rejected the second time", async () => {
  __resetNonceStoreForTest();
  __resetIdempotencyStoreForTest();
  const payload = basePayload({ idempotencyKey: randomUUID() });
  const first = await postWebhook(PORT, payload);
  assert.equal(first.status, 200);

  // Exact same payload + signature resent verbatim (same nonce) — this is
  // the attacker-replay shape, distinct from a legitimate retry (which would
  // mint a fresh nonce, see the idempotency test below).
  const second = await postWebhook(PORT, payload);
  assert.equal(second.status, 401);
  assert.equal(second.body.error, "replayed_nonce");

  const rejected = egressRows("replay_rejected");
  assert.ok(rejected.length >= 1, "replay must be journalled distinctly");
});

test("(a-control) a legitimate retry — same idempotencyKey, FRESH nonce — is not rejected as a replay", async () => {
  __resetNonceStoreForTest();
  __resetIdempotencyStoreForTest();
  const idempotencyKey = randomUUID();
  const first = await postWebhook(PORT, basePayload({ idempotencyKey, nonce: randomUUID() }));
  assert.equal(first.status, 200);

  const retry = await postWebhook(PORT, basePayload({ idempotencyKey, nonce: randomUUID() }));
  assert.equal(retry.status, 200);
  assert.deepEqual(retry.body, first.body, "retry must return the cached response, not re-execute");
});

test("(b) wrong/missing HMAC is rejected before assertEgressAllowed runs, journalled as auth_failed (not blocked)", async () => {
  __resetNonceStoreForTest();
  __resetIdempotencyStoreForTest();
  // sourceHost is NOT in the contract's allowlist — if the HMAC check ran
  // AFTER (or was skipped), this would be journalled "blocked" by
  // assertEgressAllowed instead of "auth_failed" here.
  const payload = basePayload({ sourceHost: "attacker.example" });
  const res = await postWebhook(PORT, payload, { signature: "sha256=" + "0".repeat(64) });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, "invalid_signature");

  const authFailed = egressRows("auth_failed");
  assert.ok(authFailed.length >= 1);
  const blocked = egressRows("blocked");
  assert.equal(blocked.length, 0, "a bad signature must never reach assertEgressAllowed at all");

  const missing = await postWebhook(PORT, basePayload({ sourceHost: "attacker.example", nonce: randomUUID() }), { signature: null });
  assert.equal(missing.status, 401);
  assert.equal(missing.body.error, "invalid_signature");
});

function gatedManifest() {
  return {
    manifest_version: "1",
    workflow_id: "wf-inbound-webhook-route-test",
    trigger: { type: "manual" },
    connectors: [],
    nodes: [
      { node_id: "n2", kernel_id: KERNEL_ID, kernel_digest: pinnedKernelDigest(KERNEL_ID), policy_parameters: { mode: "periods", discount_rate_pct: 5, cash_flows: [{ amount: -500, t: 0 }, { amount: 300, t: 1 }] }, gate_policy: "review_required", gate_role: "approver" },
    ],
    gates: [],
    actions: [],
  };
}

test("(c) resuming a human-review-gated run is rejected unless the contract explicitly grants run.resume — and even then the gate is re-verified, never bypassed", async () => {
  __resetNonceStoreForTest();
  __resetIdempotencyStoreForTest();
  const manifest = gatedManifest();
  const stepRunner = async (step) => runKernelNode(step, {});
  const held = await executeRun(db, { runId: "gated-run-1", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");

  // Default contract (no run.resume scope): webhook is accepted+attested,
  // but the route must never even attempt to resume the run.
  const withoutGrant = await postWebhook(PORT, basePayload({ runId: "gated-run-1", idempotencyKey: randomUUID() }));
  assert.equal(withoutGrant.status, 200);
  assert.equal(withoutGrant.body.resumeAuthorized, false);
  assert.equal(withoutGrant.body.resumed, false);

  const stillHeldRow = db.prepare("SELECT state FROM runs WHERE run_id = ?").get("gated-run-1");
  assert.equal(stillHeldRow.state, "awaiting_data", "run must remain held when the contract grants no resume capability");

  // Contract explicitly grants run.resume — the route now ATTEMPTS resume,
  // but run.mjs's own gateCheck re-verifies the §27.4 hold: since no signed
  // HA approval was ever submitted, the gate is still unsatisfied and the
  // run re-parks at awaiting_data. The grant authorizes attempting resume;
  // it can never substitute for the human approval itself.
  const withGrant = await postWebhook(PORT + 1, basePayload({ runId: "gated-run-1", idempotencyKey: randomUUID() }));
  assert.equal(withGrant.status, 200);
  assert.equal(withGrant.body.resumeAuthorized, true);
  assert.equal(withGrant.body.resumed, false, "an unsatisfied HA gate must not be bypassable via a resume grant");
  assert.equal(withGrant.body.runState, "awaiting_data");

  const stillHeldAfterGrant = db.prepare("SELECT state FROM runs WHERE run_id = ?").get("gated-run-1");
  assert.equal(stillHeldAfterGrant.state, "awaiting_data");
});
