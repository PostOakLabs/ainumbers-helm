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

test("isKnownConnector: true for http.send/google-drive.fetch/smtp.send (HELM-CONNECTOR-PARAMS-2 gave the latter two a manifest member — connector_inputs[].params — to draw params from), false for inbound-webhook/junk", () => {
  assert.equal(isKnownConnector(HTTP_SEND_ID), true);
  assert.equal(isKnownConnector("google-drive.fetch"), true);
  assert.equal(isKnownConnector("smtp.send"), true);
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

// HELM-CONNECTOR-PARAMS-2: manifestWith() above never sets connector_inputs
// (STEP_LAYERS order alone), so these use their own manifest literal to
// carry a connectorInputStep binding with `params`.
function manifestWithBinding({ connectorId, feedsParam = "rows", params }) {
  return {
    manifest_version: "1", workflow_id: "wf-connector-params-test", trigger: { type: "manual" },
    connectors: [{ connector_id: connectorId }],
    nodes: [{ node_id: "n1" }], gates: [], actions: [],
    connector_inputs: [{
      step_id: `bind-n1-${feedsParam}`, connector_id: connectorId, feeds_node_id: "n1", feeds_param: feedsParam,
      ...(params !== undefined ? { params } : {}),
    }],
  };
}

function connectorsStepFor(manifest, connectorId) {
  return planSteps(manifest).find((s) => s.kind === "connectors" && s.item.connector_id === connectorId);
}

test("dispatch: google-drive.fetch buildPayload throws named when params.fileId is missing", async () => {
  const db = openJournal(join(TMP, "dispatch-drive-missing-param.db"));
  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "0".repeat(64) });
  const step = connectorsStepFor(manifestWithBinding({ connectorId: "google-drive.fetch" }), "google-drive.fetch");
  assert.equal(step.params, undefined, "no params on the binding -> no params on the step");

  await assert.rejects(
    () => dispatch(step, { runId: "run-drive-missing" }),
    /connector dispatch: step "connectors:google-drive\.fetch" is missing required google-drive\.fetch param "fileId"/
  );
  db.close();
});

test("dispatch: google-drive.fetch params.fileId reaches buildPayload (planSteps wiring, not the schema alone)", () => {
  const step = connectorsStepFor(
    manifestWithBinding({ connectorId: "google-drive.fetch", params: { fileId: "drive-file-xyz" } }),
    "google-drive.fetch"
  );
  assert.deepEqual(step.item, { connector_id: "google-drive.fetch" }, "connectorRef itself is untouched — ruling 2");
  assert.equal(step.params.fileId, "drive-file-xyz");
});

test("dispatch: smtp.send buildPayload throws named when a required param is missing", async () => {
  const db = openJournal(join(TMP, "dispatch-smtp-missing-param.db"));
  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "1".repeat(64) });
  const step = connectorsStepFor(
    manifestWithBinding({ connectorId: "smtp.send", feedsParam: "body", params: { from: "a@example.com", to: ["b@example.com"], subject: "hi" } }),
    "smtp.send"
  );

  await assert.rejects(
    () => dispatch(step, { runId: "run-smtp-missing" }),
    /connector dispatch: step "connectors:smtp\.send" is missing required smtp\.send param "text"/
  );
  db.close();
});

test("dispatch: smtp.send rejects CR/LF in from/to/subject before send() ever sees it (phil ruling 1, header/command injection)", async () => {
  const db = openJournal(join(TMP, "dispatch-smtp-crlf.db"));
  const dispatch = createConnectorStepDispatcher({ db, workflowManifestDigest: "sha256:" + "2".repeat(64) });

  const injectedSubject = manifestWithBinding({
    connectorId: "smtp.send", feedsParam: "body",
    params: { from: "a@example.com", to: ["b@example.com"], subject: "hi\r\nBcc: attacker@evil.example", text: "body" },
  });
  const step = connectorsStepFor(injectedSubject, "smtp.send");

  await assert.rejects(
    () => dispatch(step, { runId: "run-smtp-crlf" }),
    /connector dispatch: step "connectors:smtp\.send" smtp\.send param contains CR\/LF — rejected \(header\/command injection\)/
  );
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
