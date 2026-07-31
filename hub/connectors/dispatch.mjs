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
// target_host. So today only a connector whose invocation reduces to "reach
// target_host" is dispatchable AT ALL: google-drive.fetch (needs a fileId)
// and smtp.send (needs from/to/subject/text) have no manifest member to draw
// those from and are deliberately absent from REGISTRY rather than listed
// with a payload builder that always throws — that would just relocate the
// missing-parameter error to a less honest place. Widening REGISTRY is a
// schema change (a new manifest member to carry those params), which is
// HELM-BIND-4 territory, not this row's.
//
// "actions" steps carry no connector_id (schema: {action_id, type,
// target_host}) — `type` is treated as the connector_id to invoke, since no
// other manifest member names which runtime an action targets. A `type`
// naming no known connector fails loud (the same "no silent fallback"
// doctrine HELM-BIND-2 established for unresolved bindings) rather than
// guessing at one.
//
// ⛔ NOT WIRED INTO PRODUCTION (see HELM-BIND-3 check-off): hub/run-actions.mjs
// and hub/server.mjs's resume path are the SAME code MCP's workflow.run/
// dry_run share by construction (agent-parity — one code path starts a run,
// not two hand-synced ones). Passing this dispatcher as otherKindsRunner
// there would let an MCP tools/call newly cause a connector to fetch real
// data with no human review in the loop — exactly the outcome
// HELM-DATA-BINDING-BUILD-SPEC.md §4.3 says to stop and report rather than
// ship. This module is complete and unit-tested on its own; wiring it into
// the two production call sites needs an adjudicated answer to that
// conflict first (see the row's done-note).
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadContract } from "../connector.mjs";
import { createHttpConnector, CONNECTOR_ID as HTTP_SEND_ID } from "./http-send.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

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
    const payload = entry.buildPayload({ item: step.item, stepId: step.step_id, runId, workflowManifestDigest });
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
