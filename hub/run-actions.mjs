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
import { createKernelStepRunner } from "./kernel-runner.mjs";
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

export function startWorkflowRun(db, { workflowId, templateSlug, dryRun }) {
  if (!db) throw { status: 503, error: "engine_unavailable" };
  const { manifest } = resolveRunManifest({ workflowId, templateSlug });

  const runId = randomUUID();
  const kernelStepRunner = createKernelStepRunner();
  const stepRunner = async (step, ctx) => {
    const output = await kernelStepRunner(step, ctx);
    publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
    return output;
  };

  runsInFlight++;
  executeRun(db, { runId, manifest, dryRun: !!dryRun, stepRunner, gateCheck: haGateCheckFor(db) })
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
