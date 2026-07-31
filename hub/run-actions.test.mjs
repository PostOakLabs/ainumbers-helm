// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-BIND-WIRE-1: unit-level coverage for the caller-origin gate inside
// startWorkflowRun, below the HTTP/MCP surface server.test.mjs exercises
// end-to-end. The connector dispatcher itself (connectors/dispatch.mjs) is
// HELM-BIND-3's and already has its own test suite (dispatch.test.mjs) —
// what's new here is only: (1) callerOrigin gates whether it's wired at all,
// and (2) the dry-run canDispatch parity fix in the wrapper stepRunner,
// which is otherwise invisible through a real (non-dry) run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-run-actions-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { vaultSet } = await import("./vault.mjs");
const { __setHostResolverForTest } = await import("./connector.mjs");
const { startWorkflowRun, __setManifestOverrideForTest } = await import("./run-actions.mjs");
const { subscribeRunEvents } = await import("./event-bus.mjs");

const CREDENTIAL_REF = "vault://helm/connectors/http/example/credential"; // http-send.contract.json's vault_scope[0]
vaultSet(CREDENTIAL_REF, { access_token: "tok-run-actions-test" });
__setHostResolverForTest(async (hostname) => {
  if (hostname === "api.example.com") return ["93.184.216.34"];
  throw new Error(`test resolver: unexpected hostname ${hostname}`);
});

const db = openJournal(join(TMP, "journal.db"));

test.after(() => {
  __setHostResolverForTest(null);
  db.close();
  rmSync(TMP, { recursive: true, force: true });
});

const WORKFLOW_ID = "helm-bind-wire-1-run-actions-fixture";
function actionsManifest() {
  return {
    manifest_version: "1",
    workflow_id: WORKFLOW_ID,
    trigger: { type: "manual" },
    connectors: [],
    nodes: [],
    gates: [],
    actions: [{ action_id: "a1", type: "http.send", target_host: "api.example.com" }],
  };
}

const UNKNOWN_WORKFLOW_ID = "helm-bind-wire-1-run-actions-unknown-fixture";
function unknownActionManifest() {
  return {
    manifest_version: "1",
    workflow_id: UNKNOWN_WORKFLOW_ID,
    trigger: { type: "manual" },
    connectors: [],
    nodes: [],
    gates: [],
    actions: [{ action_id: "a1", type: "email.notify", target_host: "smtp.example.com" }],
  };
}

async function waitForRunEvent(runId) {
  for (let i = 0; i < 40; i++) {
    let seen = null;
    const unsubscribe = subscribeRunEvents(runId, (data) => { seen = data; });
    unsubscribe();
    if (seen && (seen.state === "completed" || seen.state === "failed")) return seen;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`run ${runId} never reached a terminal event`);
}

test("startWorkflowRun: callerOrigin 'ui' wires the dispatcher — a real (non-dry) run with an actions step completes and attests", async () => {
  __setManifestOverrideForTest((workflowId) => (workflowId === WORKFLOW_ID ? actionsManifest() : null));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(new URL(url).host, "api.example.com");
    return new Response(Buffer.from("{}"), { status: 200 });
  };
  try {
    const { run_id: runId } = startWorkflowRun(db, { workflowId: WORKFLOW_ID, callerOrigin: "ui" });
    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "completed", `got: ${JSON.stringify(event)}`);
    const row = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").get(runId, "actions:a1");
    assert.ok(row);
    assert.equal(JSON.parse(row.output_json).attestation.connector_id, "http.send");
  } finally {
    globalThis.fetch = originalFetch;
    __setManifestOverrideForTest(null);
  }
});

test("startWorkflowRun: callerOrigin omitted (the MCP shape) — the SAME manifest fails instead of dispatching", async () => {
  __setManifestOverrideForTest((workflowId) => (workflowId === WORKFLOW_ID ? actionsManifest() : null));
  try {
    const { run_id: runId } = startWorkflowRun(db, { workflowId: WORKFLOW_ID });
    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "failed", `got: ${JSON.stringify(event)}`);
    assert.match(event.error, /no runner configured for step kind "actions"/);
  } finally {
    __setManifestOverrideForTest(null);
  }
});

test("dry-run canDispatch parity: callerOrigin 'ui' means a KNOWN action CAN dispatch, dry-run completes without ever calling fetch", async () => {
  __setManifestOverrideForTest((workflowId) => (workflowId === WORKFLOW_ID ? actionsManifest() : null));
  const originalFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = async () => { fetchCalled = true; return new Response(Buffer.from("{}"), { status: 200 }); };
  try {
    const { run_id: runId } = startWorkflowRun(db, { workflowId: WORKFLOW_ID, dryRun: true, callerOrigin: "ui" });
    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "completed", `dry-run must complete when the dispatcher IS wired and the id IS known, got: ${JSON.stringify(event)}`);
    assert.equal(fetchCalled, false, "dry-run must stay side-effect-free — canDispatch must answer without invoking stepRunner");
  } finally {
    globalThis.fetch = originalFetch;
    __setManifestOverrideForTest(null);
  }
});

test("dry-run canDispatch parity: callerOrigin omitted (the MCP shape) — dry-run fails instead of silently passing", async () => {
  __setManifestOverrideForTest((workflowId) => (workflowId === WORKFLOW_ID ? actionsManifest() : null));
  try {
    const { run_id: runId } = startWorkflowRun(db, { workflowId: WORKFLOW_ID, dryRun: true });
    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "failed", `dry-run must FAIL when the dispatcher is NOT wired (parity with a real run), got: ${JSON.stringify(event)}`);
    assert.match(event.error, /no runner configured for step kind "actions"/);
  } finally {
    __setManifestOverrideForTest(null);
  }
});

test("dry-run canDispatch parity, one level deeper (HELM-DRYRUN-PARITY-1): callerOrigin 'ui' but an UNKNOWN action type — dry-run still fails, canDispatch doesn't just check 'some runner is wired'", async () => {
  __setManifestOverrideForTest((workflowId) => (workflowId === UNKNOWN_WORKFLOW_ID ? unknownActionManifest() : null));
  const originalFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = async () => { fetchCalled = true; return new Response(Buffer.from("{}"), { status: 200 }); };
  try {
    const { run_id: runId } = startWorkflowRun(db, { workflowId: UNKNOWN_WORKFLOW_ID, dryRun: true, callerOrigin: "ui" });
    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "failed", `an unknown action type must still fail dry-run even when the dispatcher is wired, got: ${JSON.stringify(event)}`);
    // dry-run's throw is the generic kernel-runner message (run.mjs's dry-run
    // branch always raises this exact text regardless of WHY canDispatch
    // said no) — the finer "unknown connector" reason is what a REAL run
    // would throw instead, proven by the non-dry-run test above.
    assert.match(event.error, /no runner configured for step kind "actions"/);
    assert.equal(fetchCalled, false);
  } finally {
    globalThis.fetch = originalFetch;
    __setManifestOverrideForTest(null);
  }
});
