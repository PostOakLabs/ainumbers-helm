// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Shared run-kickoff core (HELM-H9): the REST /run/start route (server.mjs)
// and the MCP workflow.run/workflow.dry_run tools (mcp.mjs) BOTH call this
// one function, so the agent-parity requirement ("MCP-initiated run ≡
// UI-initiated run") holds by construction — there is only one code path
// that starts a run, not two hand-synced ones. Lives in its own module
// (not server.mjs) so mcp.mjs can import it without a server.mjs<->mcp.mjs
// import cycle.
import { randomUUID } from "node:crypto";
import { getPack } from "./packs.mjs";
import { getTemplate, buildTemplateManifest } from "./templates.mjs";
import { executeRun, manifestDigest } from "./run.mjs";
import { createKernelStepRunner, validateKernelInputs } from "./kernel-runner.mjs";
import { publishRunEvent } from "./event-bus.mjs";
import { haGateCheckFor } from "./ha-gate.mjs";
import { log } from "./log.mjs";
import { createConnectorStepDispatcher } from "./connectors/dispatch.mjs";

let runsInFlight = 0;
export function getRunsInFlightCount() {
  return runsInFlight;
}

// HELM-BIND-WIRE-1 test-only seam (same shape as connector.mjs's
// __setHostResolverForTest): lets a test resolve a workflow_id to an
// arbitrary manifest — e.g. one carrying a "connectors"/"actions" step — so
// the real server.mjs/mcp.mjs call sites can be exercised end-to-end without
// a schema-valid compiled pack. No shipped pack has a connector step yet
// (compile-packs.mjs:101 hardcodes connectors: []; HELM-BIND-4, not this
// row, is what will make one) and packs.mjs has no such seam of its own
// (out of this row's fence). Production never sets this; resolveRunManifest
// falls through to the real getPack/getTemplate lookup whenever it's unset
// or returns nothing for the given id.
let manifestOverrideForTest = null;
export function __setManifestOverrideForTest(fn) {
  manifestOverrideForTest = fn;
}

// Throws a {status, error} shaped object for the caller to translate into
// its own transport's error format (HTTP 4xx vs JSON-RPC -32602/-32601).
export function resolveRunManifest({ workflowId, templateSlug }) {
  if (!templateSlug && workflowId && manifestOverrideForTest) {
    const manifest = manifestOverrideForTest(workflowId);
    if (manifest) return { workflowId, manifest };
  }
  if (templateSlug) {
    const template = getTemplate(templateSlug);
    if (!template) throw { status: 404, error: "template_not_found" };
    const manifest = buildTemplateManifest(template);
    if (!manifest) throw { status: 404, error: "workflow_not_found" };
    return { workflowId: template.workflow_id, manifest };
  }
  if (!workflowId) throw { status: 400, error: "missing_workflow_id" };
  const pack = getPack(workflowId);
  if (!pack) throw { status: 404, error: "workflow_not_found" };
  return { workflowId, manifest: pack.manifest };
}

// HELM-BIND-0 §1.2: caller-supplied inputs are keyed by node_id and land in
// that node's policy_parameters, replacing the manifest's own default
// (usually none). Validated against the node's kernel BEFORE the manifest
// clone is handed to executeRun — an invalid blob never reaches `validated`,
// let alone buildArtifact, because startWorkflowRun throws synchronously
// before a run row is ever inserted.
function applyInputs(manifest, inputs) {
  if (!inputs) return manifest;
  const clone = JSON.parse(JSON.stringify(manifest));
  clone.nodes = (clone.nodes ?? []).map((node) => {
    if (!Object.prototype.hasOwnProperty.call(inputs, node.node_id)) return node;
    const supplied = inputs[node.node_id];
    const check = validateKernelInputs(node.kernel_id, supplied);
    if (!check.ok) throw { status: 400, error: "invalid_inputs", detail: `node "${node.node_id}": ${check.error}` };
    return { ...node, policy_parameters: supplied };
  });
  return clone;
}

// HELM-BIND-0 §1.4: a "nodes" step whose policy_parameters (whatever their
// origin — caller-supplied above, or the manifest's own unfilled default)
// would make its kernel throw is NOT a hard failure — it's a run that needs
// data it doesn't have yet. Only holds for nodes the caller did NOT supply:
// a caller who supplied inputs and still failed validation already got
// rejected above (§1.2), so a hold here only ever means "nobody tried".
// Composed ahead of haGateCheckFor so an HA approval gate still runs once
// data is present. Reuses the existing `running -> awaiting_data -> running`
// transition (run.mjs) — no new lifecycle state.
function missingDataGateCheck(suppliedNodeIds) {
  return async (step) => {
    if (step.kind !== "nodes" || suppliedNodeIds.has(step.item.node_id)) return { held: false };
    const check = validateKernelInputs(step.item.kernel_id, step.item.policy_parameters);
    if (check.ok) return { held: false };
    return { held: true, reason: `awaiting_data: node "${step.item.node_id}" needs policy_parameters (${check.error})` };
  };
}

function composeGateChecks(checks) {
  return async (step, ctx) => {
    for (const check of checks) {
      const result = await check(step, ctx);
      if (result?.held) return result;
    }
    return { held: false };
  };
}

// callerOrigin (HELM-BIND-WIRE-1 §4.3): a caller-supplied literal, not
// inferred from anything on the wire. server.mjs's REST /run/start is the
// ONLY call site that passes "ui" (handleRunStart, below). mcp.mjs's
// workflow.run/workflow.dry_run tool calls this same function (that sharing
// is the whole point of this module, per the file-header comment) but is
// fenced out of this row — its call site is unedited and has never passed
// this field, so callerOrigin arrives here as undefined for every MCP
// call, structurally, not by a check either of us added. Anything other
// than the literal "ui" fails CLOSED: otherKindsRunner stays null, so
// createKernelStepRunner throws on a "connectors"/"actions" step exactly as
// it does today for every caller — no new agent-reachable capability.
export function startWorkflowRun(db, { workflowId, templateSlug, dryRun, inputs, callerOrigin }) {
  if (!db) throw { status: 503, error: "engine_unavailable" };
  if (inputs !== undefined && (typeof inputs !== "object" || inputs === null || Array.isArray(inputs))) {
    throw { status: 400, error: "invalid_inputs", detail: "inputs must be an object keyed by node_id" };
  }
  const { manifest: resolvedManifest } = resolveRunManifest({ workflowId, templateSlug });
  const manifest = applyInputs(resolvedManifest, inputs);
  const suppliedNodeIds = new Set(inputs ? Object.keys(inputs) : []);

  const runId = randomUUID();
  const workflowManifestDigest = manifestDigest(manifest);
  const kernelStepRunner = createKernelStepRunner(
    callerOrigin === "ui" ? { otherKindsRunner: createConnectorStepDispatcher({ db, workflowManifestDigest }) } : {}
  );
  const stepRunner = async (step, ctx) => {
    const output = await kernelStepRunner(step, ctx);
    publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
    return output;
  };
  // HELM-BIND-WIRE-1: canDispatch must stay in step with stepRunner
  // (DRYRUN-PARITY-1) — but run.mjs's dry-run path reads it off the exact
  // object passed as `stepRunner` into executeRun, which is this wrapper,
  // not kernelStepRunner. Without this line the wrapper carries no
  // canDispatch at all, so `dryRun && stepRunner.canDispatch && ...` never
  // fires and dry-run silently skips the "would a real run throw on this
  // kind" check — a latent gap that never surfaced because otherKindsRunner
  // was never wired before this row.
  stepRunner.canDispatch = kernelStepRunner.canDispatch;
  const gateCheck = composeGateChecks([missingDataGateCheck(suppliedNodeIds), haGateCheckFor(db)]);

  runsInFlight++;
  executeRun(db, { runId, manifest, dryRun: !!dryRun, stepRunner, gateCheck })
    .then((result) => publishRunEvent(runId, {
      run_id: runId, state: result.state, execution_hash: result.executionHash, held: result.held ?? null,
    }))
    .catch((err) => {
      log.error("run engine: run failed", { runId, workflowId, error: String(err?.message || err) });
      publishRunEvent(runId, { run_id: runId, state: "failed", error: String(err?.message || err) });
    })
    .finally(() => runsInFlight--);

  // run_id (snake_case): the REST wire contract handleRunStart has always
  // returned (run-routes.test.mjs asserts it) — preserved here so this
  // refactor doesn't silently rename the field out from under existing
  // clients. MCP's workflow.run/dry_run tools read runId off this same
  // object (mcp.mjs's `started.runId`), which JS lets it do either way.
  return { run_id: runId, runId, state: "queued" };
}
