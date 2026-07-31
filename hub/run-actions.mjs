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
import { executeRun } from "./run.mjs";
import { createKernelStepRunner, validateKernelInputs } from "./kernel-runner.mjs";
import { publishRunEvent } from "./event-bus.mjs";
import { haGateCheckFor } from "./ha-gate.mjs";
import { log } from "./log.mjs";

let runsInFlight = 0;
export function getRunsInFlightCount() {
  return runsInFlight;
}

// Throws a {status, error} shaped object for the caller to translate into
// its own transport's error format (HTTP 4xx vs JSON-RPC -32602/-32601).
export function resolveRunManifest({ workflowId, templateSlug }) {
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

export function startWorkflowRun(db, { workflowId, templateSlug, dryRun, inputs }) {
  if (!db) throw { status: 503, error: "engine_unavailable" };
  if (inputs !== undefined && (typeof inputs !== "object" || inputs === null || Array.isArray(inputs))) {
    throw { status: 400, error: "invalid_inputs", detail: "inputs must be an object keyed by node_id" };
  }
  const { manifest: resolvedManifest } = resolveRunManifest({ workflowId, templateSlug });
  const manifest = applyInputs(resolvedManifest, inputs);
  const suppliedNodeIds = new Set(inputs ? Object.keys(inputs) : []);

  const runId = randomUUID();
  const kernelStepRunner = createKernelStepRunner();
  const stepRunner = async (step, ctx) => {
    const output = await kernelStepRunner(step, ctx);
    publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
    return output;
  };
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
