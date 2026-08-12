// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-BIND-3 §4.1: routes "connectors" and "actions" run steps to the
// EXISTING, tested connector runtime (connector.mjs's DNS-rebind defence,
// egress allowlist, secret vault, connector_attestation builder) instead of
// createKernelStepRunner()'s bare "no runner configured" throw. Not a new
// runtime — http.send below is one of the connector modules that already
// ships with its own passing contract test suite; this module only looks it
// up and calls it.
//
// A step's item never carries more than the schema allows — connectorRef is
// {connector_id, contract_digest}; only `actions` items also carry
// target_host. http.send draws on that. google-drive.fetch and smtp.send
// need config connectorRef can't carry (a fileId; from/to/subject/text) —
// HELM-CONNECTOR-PARAMS-2 supplies it via a DIFFERENT manifest member,
// `connector_inputs[].params` ($defs.connectorInputStep, curated/compile-time
// only — never a live workflow.run caller value, phil ruling 3). run.mjs's
// planSteps() attaches a matching binding's `params` onto the `connectors`
// step for the same connector_id (step.params, step-local metadata — the
// connectorRef item itself is never touched, phil ruling 2). Below,
// runConnectorStep() passes step.params through to buildPayload().
//
// "actions" steps carry no connector_id (schema: {action_id, type,
// target_host}) — `type` is treated as the connector_id to invoke, since no
// other manifest member names which runtime an action targets. A `type`
// naming no known connector fails loud (the same "no silent fallback"
// doctrine HELM-BIND-2 established for unresolved bindings) rather than
// guessing at one.
//
// ⛔ dispatch.mjs is wired for authenticated-UI-triggered runs (`callerOrigin:
// "ui"`, via hub/run-actions.mjs since HELM-BIND-WIRE-1 — server.mjs's
// `POST /run/start` is the one call site that sets it, behind the same
// Host+Origin+Bearer gate as every other mutating route) — it is still
// UNWIRED for MCP `tools/call` (workflow.run/dry_run never set
// callerOrigin:"ui"), which is what HELM-BIND-3's still-open conflict
// (an MCP call newly causing a real fetch/send with no human review in the
// loop) actually concerns. PHIL-HELM-PARAMS-REVIEW-1 found the "NOT WIRED
// INTO PRODUCTION" wording this comment used to carry was stale relative to
// that landed wiring — corrected here rather than restated. Severity stays
// LOW because `params` values are curated/compile-time only (ruling 3): an
// authenticated operator running a workflow with a connector step causes the
// same curated fetch/send any run of that pack would, regardless of trigger
// path — this is a documentation-accuracy correction, not a new capability.
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadContract } from "../connector.mjs";
import { createHttpConnector, CONNECTOR_ID as HTTP_SEND_ID } from "./http-send.mjs";
import { createGoogleDriveFetchConnector, CONNECTOR_ID as GOOGLE_DRIVE_FETCH_ID } from "./google-drive-fetch.mjs";
import { createSmtpConnector, CONNECTOR_ID as SMTP_SEND_ID } from "./smtp-send.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

const CRLF = /[\r\n]/;

function requireParam(params, key, connectorId, stepId) {
  const value = params?.[key];
  if (value === undefined || value === null || value === "") {
    throw new Error(`connector dispatch: step "${stepId}" is missing required ${connectorId} param "${key}"`);
  }
  return value;
}

// Contract-pinned host:port (e.g. "smtp.example.com:587") -> [host, port].
// smtp.send's payload needs them split; every other connector either has no
// fixed host (http.send draws target_host from the manifest) or takes a
// bare host (google-drive.fetch is HTTPS-443 by construction).
function splitHostPort(hostPort) {
  const idx = hostPort.lastIndexOf(":");
  if (idx === -1) throw new Error(`connector dispatch: contract allowed_hosts entry "${hostPort}" has no port`);
  return [hostPort.slice(0, idx), hostPort.slice(idx + 1)];
}

const REGISTRY = {
  [HTTP_SEND_ID]: {
    contractPath: join(HERE, "http-send.contract.json"),
    create: createHttpConnector,
    buildPayload: ({ item, stepId, runId, workflowManifestDigest }) => {
      if (!item.target_host) {
        throw new Error(
          `connector dispatch: step "${stepId}" has no target_host to build a request from — only "actions" steps carry one today`
        );
      }
      return { url: `https://${item.target_host}`, method: "GET", runId, workflowManifestDigest };
    },
  },
  [GOOGLE_DRIVE_FETCH_ID]: {
    contractPath: join(HERE, "google-drive-fetch.contract.json"),
    create: createGoogleDriveFetchConnector,
    // params sourced from connector_inputs[].params (HELM-CONNECTOR-PARAMS-2,
    // curated-only — see file header). Missing-param-throws, same pattern
    // http.send uses for target_host above.
    buildPayload: ({ params, stepId, runId, workflowManifestDigest }) => {
      const fileId = requireParam(params, "fileId", GOOGLE_DRIVE_FETCH_ID, stepId);
      return { fileId, runId, workflowManifestDigest };
    },
  },
  [SMTP_SEND_ID]: {
    contractPath: join(HERE, "smtp-send.contract.json"),
    create: createSmtpConnector,
    // params sourced from connector_inputs[].params, same provenance as
    // google-drive.fetch above. host/port are NOT part of params (curated
    // config carries only what the fetch/send itself needs) — they come from
    // the connector's own contract.allowed_hosts, the single pinned
    // destination assertEgressAllowed already gates SEND against.
    //
    // Phil ruling 1 (schema-vs-connector split): the schema's `pattern`
    // (workflow-manifest.schema.json $defs.connectorInputStep.params) is the
    // cheap first CR/LF gate on a curated entry; THIS check is the mandatory
    // connector-adjacent one — buildPayload is the one and only place that
    // turns a manifest's params into a live smtp.send() call in this
    // codebase today, so rejecting CR/LF here before send() ever sees the
    // value closes the header/command-injection shape ruling 1 confirmed
    // (raw wire-protocol interpolation, zero validation inside smtp-send.mjs
    // itself). ⚠ Ruling 1 also names smtp-send.mjs's own send() as the
    // last-mile, structurally-unbypassable gate (defense-in-depth, matching
    // this module's own house style) — that edit is OUTSIDE this row's fence
    // (helm/hub/connectors/dispatch.mjs only) and is NOT made here; flagging
    // it as a receiving item for a fast-follow row rather than silently
    // treating this buildPayload check as the full guarantee ruling 1 asked
    // for.
    buildPayload: ({ params, contract, stepId, runId, workflowManifestDigest }) => {
      const from = requireParam(params, "from", SMTP_SEND_ID, stepId);
      const to = requireParam(params, "to", SMTP_SEND_ID, stepId);
      const subject = requireParam(params, "subject", SMTP_SEND_ID, stepId);
      const text = requireParam(params, "text", SMTP_SEND_ID, stepId);
      if (CRLF.test(from) || (Array.isArray(to) ? to.some((r) => CRLF.test(r)) : CRLF.test(to)) || CRLF.test(subject)) {
        throw new Error(
          `connector dispatch: step "${stepId}" smtp.send param contains CR/LF — rejected (header/command injection)`
        );
      }
      const [host, port] = splitHostPort(contract.allowed_hosts[0]);
      return { host, port: Number(port), from, to, subject, text, runId, workflowManifestDigest };
    },
  },
};

function connectorIdFor(step) {
  return step.kind === "connectors" ? step.item.connector_id : step.item.type;
}

export function isKnownConnector(connectorId) {
  return Object.prototype.hasOwnProperty.call(REGISTRY, connectorId);
}

function requireEntry(connectorId, stepId) {
  const entry = REGISTRY[connectorId];
  if (!entry) {
    throw new Error(
      `connector dispatch: step "${stepId}" names unknown connector "${connectorId}" (known: ${Object.keys(REGISTRY).join(", ")})`
    );
  }
  return entry;
}

async function runConnectorStep({ db, step, connectorId, runId, workflowManifestDigest }) {
  const entry = requireEntry(connectorId, step.step_id);
  const { contract, contractDigest } = loadContract(entry.contractPath);
  if (step.item.contract_digest && step.item.contract_digest !== contractDigest) {
    throw new Error(
      `connector dispatch: step "${step.step_id}" contract_digest mismatch for "${connectorId}" — manifest pins ${step.item.contract_digest}, on-disk contract is ${contractDigest}`
    );
  }
  const connector = entry.create({ db, contract, contractDigest });
  await connector.init({});
  try {
    const payload = entry.buildPayload({
      item: step.item,
      params: step.params,
      contract,
      stepId: step.step_id,
      runId,
      workflowManifestDigest,
    });
    return await connector.send(payload);
  } finally {
    await connector.dispose();
  }
}

// createKernelStepRunner's otherKindsRunner contract: async (step, ctx) ->
// JSON-serializable output. The returned function also carries `canDispatch`
// (mirroring kernel-runner.mjs's own convention) so HELM-DRYRUN-PARITY-1
// holds one level deeper than "some runner is configured" — kernel-runner.mjs
// consults it, when present, to ask "would THIS step's connector/action id
// resolve" without invoking send().
export function createConnectorStepDispatcher({ db, workflowManifestDigest }) {
  async function dispatch(step, ctx = {}) {
    if (step.kind !== "connectors" && step.kind !== "actions") {
      throw new Error(`connector dispatch: step "${step.step_id}" has unsupported kind "${step.kind}"`);
    }
    return runConnectorStep({
      db,
      step,
      connectorId: connectorIdFor(step),
      runId: ctx.runId,
      workflowManifestDigest,
    });
  }
  dispatch.canDispatch = (step) =>
    (step.kind === "connectors" || step.kind === "actions") && isKnownConnector(connectorIdFor(step));
  return dispatch;
}
