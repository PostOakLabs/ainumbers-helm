// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-BIND-3: proves the connector-step dispatcher works end-to-end against
// the REAL connector runtime (not a mock of it) and that canDispatch predicts
// exactly what dispatch() will do — the HELM-DRYRUN-PARITY-1 property this
// row's §4.1 exists to uphold one level deeper than "some runner exists".
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-connector-dispatch-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("../journal.mjs");
const { __setHostResolverForTest } = await import("../connector.mjs");
const { createKernelStepRunner } = await import("../kernel-runner.mjs");
const { planSteps } = await import("../run.mjs");
const { createConnectorStepDispatcher, isKnownConnector } = await import("./dispatch.mjs");
const { CONNECTOR_ID: HTTP_SEND_ID } = await import("./http-send.mjs");

__setHostResolverForTest(async (hostname) => {
  if (hostname === "api.example.com") return ["93.184.216.34"];
  throw new Error(`test resolver: unexpected hostname ${hostname}`);
});
process.on("exit", () => __setHostResolverForTest(null));

const ATTESTATION_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "..", "schema", "objects", "connector_attestation.schema.json"), "utf8")
);

function manifestWith({ connectors = [], actions = [] } = {}) {
  return {
    manifest_version: "1", workflow_id: "wf-dispatch-test", trigger: { type: "manual" },
    connectors, nodes: [], gates: [], actions,
  };
}

test("isKnownConnector: true for http.send, false for smtp.send/google-drive.fetch/inbound-webhook/junk (none of the others has a manifest member to draw params from)", () => {
  assert.equal(isKnownConnector(HTTP_SEND_ID), true);
  assert.equal(isKnownConnector("smtp.send"), false);
  assert.equal(isKnownConnector("google-drive.fetch"), false);
  assert.equal(isKnownConnector("inbound-webhook"), false);
  assert.equal(isKnownConnector("not-a-connector"), false);
});

test("dispatch: a bare `connectors` step for http.send has no target_host to draw on and fails loud, named — not a raw 'Invalid URL'", async () => {
  const db = openJournal(join(TMP, "dispatch-no-target-host.db"));
  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "a".repeat(64) });
  const [step] = planSteps(manifestWith({ connectors: [{ connector_id: HTTP_SEND_ID }] }));

  await assert.rejects(
    () => dispatch(step, { runId: "run-1" }),
    /connector dispatch: step "connectors:http\.send" has no target_host to build a request from/
  );
  db.close();
});

test("dispatch: actions step treats `type` as the connector_id and `target_host` as the destination", async () => {
  const db = openJournal(join(TMP, "dispatch-action.db"));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(new URL(url).host, "api.example.com");
    return new Response(Buffer.from("{}"), { status: 200 });
  };

  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "b".repeat(64) });
  const [step] = planSteps(manifestWith({ actions: [{ action_id: "a1", type: HTTP_SEND_ID, target_host: "api.example.com" }] }));
  const result = await dispatch(step, { runId: "run-2" });

  assert.equal(result.attestation.endpoint_host, "api.example.com");
  assert.equal(result.attestation.connector_id, HTTP_SEND_ID);
  const errs = validate(ATTESTATION_SCHEMA, result.attestation);
  assert.deepEqual(errs, []);

  globalThis.fetch = originalFetch;
  db.close();
});

test("dispatch: unknown connector_id fails loud, named, with the step_id in the message", async () => {
  const db = openJournal(join(TMP, "dispatch-unknown.db"));
  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "c".repeat(64) });
  const [step] = planSteps(manifestWith({ connectors: [{ connector_id: "not-a-connector" }] }));

  await assert.rejects(
    () => dispatch(step, { runId: "run-3" }),
    /connector dispatch: step "connectors:not-a-connector" names unknown connector "not-a-connector"/
  );
  db.close();
});

test("dispatch: unknown action type fails loud the same way", async () => {
  const db = openJournal(join(TMP, "dispatch-unknown-action.db"));
  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "d".repeat(64) });
  const [step] = planSteps(manifestWith({ actions: [{ action_id: "a1", type: "email.notify", target_host: "smtp.example.com" }] }));

  await assert.rejects(() => dispatch(step, { runId: "run-4" }), /unknown connector "email\.notify"/);
  db.close();
});

test("dispatch.canDispatch: predicts exactly what dispatch() will do, for both known and unknown ids", () => {
  const dispatch = createConnectorStepDispatcher({ db: null, workflowManifestDigest: "sha256:" + "e".repeat(64) });
  const [known] = planSteps(manifestWith({ connectors: [{ connector_id: HTTP_SEND_ID }] }));
  const [unknown] = planSteps(manifestWith({ connectors: [{ connector_id: "nope" }] }));
  assert.equal(dispatch.canDispatch(known), true);
  assert.equal(dispatch.canDispatch(unknown), false);
});

test("HELM-DRYRUN-PARITY-1 (one level deeper): dry-run predicts a throw for an unknown connector_id WITHOUT invoking send()", async () => {
  const db = openJournal(join(TMP, "dispatch-dryrun.db"));
  let sendCalled = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { sendCalled = true; return new Response(Buffer.from("{}"), { status: 200 }); };

  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "f".repeat(64) });
  const stepRunner = createKernelStepRunner({ otherKindsRunner: dispatch });
  const [step] = planSteps(manifestWith({ connectors: [{ connector_id: "nope" }] }));

  assert.equal(stepRunner.canDispatch(step), false);
  assert.equal(sendCalled, false);

  globalThis.fetch = originalFetch;
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
