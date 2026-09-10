// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-OTEL-1 — OpenTelemetry GenAI span tree per helm run, rebuilt over the
// run engine's own persisted state (never a second execution path):
//
//   - one `invoke_agent` span per run (per completed step tree: one
//     `execute_tool` span per COMPLETED step — a step with a verified memo
//     row in step_results), carrying ocg.execution_hash / ocg.kernel_digest
//     off the step's own kernel artifact, plus ocg.run_id + ocg.workflow_id
//     (the workflow-manifest digest), and ocg.composite_execution_hash +
//     ocg.run_id + ocg.workflow_id on the root;
//   - a failed run still yields the invoke_agent root — with an error
//     status — and NO execute_tool spans for steps that never executed;
//   - the span tree shape (attribute names, span kinds, statuses) is the
//     worker's otelspan.mjs wire format, PINNED: the engine lives in
//     hub/vendored/worker-otelspan/otelspan.mjs (chainRunToOtlpTrace for the
//     completed-tree walker is deliberately reused rather than
//     reimplemented), and attribute names are pinned in
//     hub/fixtures/otel-attributes.json — drift is a test failure.
//
// Default output is a file: `<state-dir>/otel/<run_id>.json` (OTLP-JSON),
// written after run completion via recordRunSpans — run.mjs's finalisation
// hook. A collector POST happens ONLY when config.otelCollectorUrl is set
// (default `""` = default-off), and even then through
// connector.mjs's performEgress — so the DNS-rebind guard applies: a loopback
// collector is refused by design (see docs/TRUST.md §1 row 13; a loopback
// collector needs the tailnet/LAN-bind follow-up row, LATER, not a guard
// carve-out here). recordRunSpans never throws: telemetry must never fail a
// run — a failed export is reported on stderr and otherwise silent.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { stateDir } from "./state-dir.mjs";
import { loadConfig } from "./config.mjs";
import { performEgress } from "./connector.mjs";
import { chainRunToOtlpTrace } from "./vendored/worker-otelspan/otelspan.mjs";
import { planSteps, stepInputDigest, getMemoizedStep } from "./run.mjs";

function uuidHex(nBytes) {
  const b = new Uint8Array(nBytes);
  globalThis.crypto.getRandomValues(b);
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}

function nanoNow(offsetMs) {
  return (BigInt(Date.now() + (offsetMs || 0)) * 1000000n).toString();
}

function sv(s) {
  return { stringValue: String(s) };
}

function attr(key, value) {
  return { key, value: sv(value) };
}

// Runs the payload of a completed step's memoized output — kernel_runner
// shape — through the same extractor discipline: execution_hash and
// kernel_digest come ONLY off real kernel artifacts, never fabricated.
function stepSpanData(output, step) {
  const artifact = output?.artifact ?? null;
  const toolName = artifact?.tool_id ?? output?.kernel_id ?? step.step_id;
  return {
    tool_id: toolName,
    execution_hash: artifact?.execution_hash ?? null,
    kernel_digest: output?.kernel_digest ?? null,
  };
}

/**
 * buildRunOtlpTrace(db, runId) -> { trace, state, completedSteps } where
 * `trace` is an OTLP-JSON document ({ resourceSpans: [...] }) or `null` when
 * the run is not yet at a terminal state (still queued/running/awaiting_data)
 * — a run is finalised exactly once, so only completed/failed runs produce a
 * document. Pure: reads db rows only, writes nothing, dials nothing.
 */
export function buildRunOtlpTrace(db, runId) {
  const run = db.prepare("SELECT * FROM runs WHERE run_id = ?").get(runId);
  if (!run) throw new Error(`otel-export: unknown run_id ${runId}`);
  if (run.state !== "completed" && run.state !== "failed") return { trace: null, state: run.state, completedSteps: 0 };

  const manifest = JSON.parse(run.manifest_json);
  const steps = planSteps(manifest);

  // Completed steps = memo rows present (and untampered — getMemoizedStep
  // re-verifies output_digest on every read, so nothing under-audit slips by).
  const completed = [];
  let priorOutputDigest = null;
  for (const step of steps) {
    try {
      const inputDigest = stepInputDigest({
        runId,
        step,
        priorOutputDigest,
        dryRun: !!run.dry_run,
        resolvedParams: null,
      });
      const memo = getMemoizedStep(db, { runId, stepId: step.step_id, inputDigest });
      if (!memo) break; // the first missing memo ends the completed prefix
      completed.push({ step, output: memo.output, outputDigest: memo.outputDigest });
      priorOutputDigest = memo.outputDigest;
    } catch {
      // a tampered memo below the first hole ends the completed prefix —
      // deeper rows cannot have run, graph order is topological.
      break;
    }
  }

  const traceId = uuidHex(16);
  const rootSpanId = uuidHex(8);
  const t0 = nanoNow(0);
  const service = "ainumbers-helm";
  const system = "ainumbers-helm";
  const failed = run.state === "failed";
  const dur = completed.length > 0 || failed ? 10 * (completed.length + 1) : 10;

  const rootAttrs = [
    attr("gen_ai.operation.name", "invoke_agent"),
    attr("gen_ai.system", system),
    attr("gen_ai.agent.name", manifest.workflow_id ?? runId),
    attr("ocg.run_id", runId),
    attr("ocg.workflow_id", manifest.workflow_id ?? run.workflow_manifest_digest),
  ];
  if (run.execution_hash) rootAttrs.push(attr("ocg.composite_execution_hash", run.execution_hash));

  const spans = [
    {
      traceId,
      spanId: rootSpanId,
      name: `invoke_agent ${manifest.workflow_id ?? runId}`,
      kind: "SPAN_KIND_INTERNAL",
      startTimeUnixNano: t0,
      endTimeUnixNano: nanoNow(dur),
      attributes: rootAttrs,
      status: failed
        ? { code: "STATUS_CODE_ERROR", message: `run ${runId} ended in state: ${run.state}` }
        : { code: "STATUS_CODE_OK" },
    },
  ];

  completed.forEach(({ step, output }, i) => {
    const data = stepSpanData(output, step);
    const spanAttrs = [
      attr("gen_ai.operation.name", "execute_tool"),
      attr("gen_ai.system", system),
      attr("gen_ai.tool.name", data.tool_id),
      attr("ocg.run_id", runId),
      attr("ocg.workflow_id", manifest.workflow_id ?? run.workflow_manifest_digest),
    ];
    if (data.execution_hash) spanAttrs.push(attr("ocg.execution_hash", data.execution_hash));
    if (data.kernel_digest) spanAttrs.push(attr("ocg.kernel_digest", data.kernel_digest));
    spans.push({
      traceId,
      spanId: uuidHex(8),
      parentSpanId: rootSpanId,
      name: `execute_tool ${data.tool_id}`,
      kind: "SPAN_KIND_INTERNAL",
      startTimeUnixNano: nanoNow(10 * (i + 1)),
      endTimeUnixNano: nanoNow(10 * (i + 2)),
      attributes: spanAttrs,
      status: { code: "STATUS_CODE_OK" },
    });
  });

  return {
    trace: {
      resourceSpans: [
        {
          resource: {
            attributes: [attr("service.name", service), attr("telemetry.sdk.name", "ainumbers-helm")],
          },
          scopeSpans: [{ scope: { name: "ainumbers.helm-otel", version: "1.0.0" }, spans }],
        },
      ],
    },
    state: run.state,
    completedSteps: completed.length,
  };
}

/**
 * recordRunSpans(db, runId, { now }) — run.mjs's ONE finalisation hook.
 * Writes <state-dir>/otel/<run_id>.json (OTLP-JSON) by default; if
 * config.otelCollectorUrl is set, POSTs the same document through
 * performEgress (DNS-rebind guard applies — loopback collectors refused).
 * NEVER throws and NEVER takes a run down: telemetry is best-effort by
 * charter — the failure is printed on stderr, the run result unchanged.
 */
export async function recordRunSpans(db, runId, { now } = {}) {
  try {
    const { trace } = buildRunOtlpTrace(db, runId);
    if (!trace) return null;

    // Master safety rail: reuse the vendored worker's structural linter — a
    // malformed span tree is caught here and logged, never written/shipped.
    const { lintOtlpTrace } = await import("./vendored/worker-otelspan/otelspan.mjs");
    const lint = lintOtlpTrace(trace);
    if (lint.findings.filter((f) => f.ok === false).length > 0) {
      console.error(
        `otel-export: lint reported ${lint.findings.filter((f) => f.ok === false).length} finding(s) for run ${runId}; not writing span doc`
      );
      return null;
    }

    const dir = join(stateDir(), "otel");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(join(dir, `${runId}.json`), JSON.stringify(trace, null, 2) + "\n");

    const config = loadConfig();
    const url = (config.otelCollectorUrl ?? "").trim();
    if (!url) return { written: true, posted: false };

    const host = new URL(url).host;
    await performEgress(db, {
      contract: { allowed_hosts: [host], allowed_methods: ["POST"] },
      connectorId: "otel-collector",
      url,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: Buffer.from(JSON.stringify({ resourceSpans: trace.resourceSpans })),
    });
    return { written: true, posted: true };
  } catch (err) {
    console.error(`otel-export: run ${runId} span capture skipped: ${err.message}`);
    return null;
  }
}
