// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// `helm check` (HELMCHECK-BUILD-1, HELM-CHECK-BUILD-SPEC.md): recomputes one
// pack's kernel against a reviewer's own extract and diffs the result against
// an asserted value — no daemon, no prior run, a stranger's file. ONE KERNEL,
// TWO SURFACES: this module never re-implements a pack's arithmetic. It loads
// the compiled pack (getPack, same lookup workflow-export.mjs/export-bpmn.mjs
// already use), builds ONE step object, and hands it to kernel-runner.mjs's
// runKernelNode — the exact function a live run.mjs execution dispatches a
// "nodes" step to. A pack's own kernel is trusted to report whether its
// recomputed figures match what was asserted (see CHECK_ADAPTERS below) —
// this file only classifies that already-computed answer into an exit code.
import { getPack } from "./packs.mjs";
import { validateKernelInputs, runKernelNode } from "./kernel-runner.mjs";
import { policyParametersHash } from "./vendored/ocg/kernels/_hash.mjs";
import { sealBundleObject, assembleBundle } from "./bundle.mjs";
import { loadOrCreateKeys } from "./keys.mjs";
import { anchorRfc3161 } from "./anchor-client.mjs";
import { log } from "./log.mjs";

// Exit codes (HELM-CHECK-BUILD-SPEC.md § Exit codes) — distinct per row's
// explicit requirement: a diff must never share a code with a failed run, and
// `2` (no assertion) must never be readable as "checked and passed".
export const EXIT = Object.freeze({
  MATCH: 0,
  DIFFERS: 1,
  NO_ASSERTION: 2,
  INSUFFICIENT_INPUT: 3,
  USAGE_ERROR: 4,
  SCOPE_DISAGREEMENT: 5,
});

// Per-pack adapter: declares (a) which policy_parameters key the input
// file's top-level `asserted` value feeds (HELM-CHECK-BUILD-SPEC.md §4: "the
// `asserted` key maps to `asserted_totals`"), and (b) where in the kernel's
// OWN output_payload to read the comparison it already computed. Adding a
// future pack to `helm check` means adding one entry here, never a second
// diff implementation — a pack whose kernel does NOT self-diff is out of
// scope for this row (DELEGATED-AUTHORITY-BDX-BUILD-SPEC.md §4 is the only
// pack this row registers).
const CHECK_ADAPTERS = {
  "pack-art-508-recompute-bordereau": {
    assertedInputKey: "asserted_totals",
    comparisonStateField: "comparison_state",
    diffField: "diff",
    // Scope disagreement (exit 5): `currency` is the one field the asserted
    // totals and the recomputed rows both carry that DEFINES what population
    // is being compared (HELM-CHECK-BUILD-SPEC.md § Scope disagreement,
    // trigger 2 — "asserted and inputs disagree on a scope-defining field").
    // Detected structurally: zero overlap between the currencies named in
    // `asserted` and the currencies the rows actually foot to means the two
    // sides are not describing the same bordereau, not that the numbers
    // differ.
    scopeCurrencyField: "currencies",
  },
};

function currenciesOf(list) {
  const out = new Set();
  for (const row of Array.isArray(list) ? list : [list]) {
    const ccy = row && typeof row === "object" ? row.currency : undefined;
    if (typeof ccy === "string" && ccy.trim()) out.add(ccy.trim().toUpperCase());
  }
  return out;
}

function intersects(a, b) {
  for (const v of a) if (b.has(v)) return true;
  return false;
}

// Reads input_file's structural contract (HELM-CHECK-BUILD-SPEC.md § What it
// does, step 2): a JSON document with `inputs` (fed to the kernel verbatim)
// and an optional `asserted` (the producer's claimed output). Returns
// { ok: true, inputs, asserted } or { ok: false, code, message }.
function readInputFile(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, code: EXIT.USAGE_ERROR, message: `input_file is not valid JSON: ${String(err?.message || err)}` };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, code: EXIT.INSUFFICIENT_INPUT, message: "input_file must be a JSON object with an `inputs` key" };
  }
  if (parsed.inputs === undefined || parsed.inputs === null || typeof parsed.inputs !== "object" || Array.isArray(parsed.inputs)) {
    return { ok: false, code: EXIT.INSUFFICIENT_INPUT, message: "input_file is missing a usable `inputs` object" };
  }
  const hasAsserted = Object.prototype.hasOwnProperty.call(parsed, "asserted") && parsed.asserted !== undefined && parsed.asserted !== null;
  return { ok: true, inputs: parsed.inputs, asserted: hasAsserted ? parsed.asserted : undefined };
}

// Runs the pack's kernel via kernel-runner.mjs's runKernelNode — the SAME
// execution path a live run dispatches a "nodes" step to. No new execution
// path, per the row's fence.
async function runPackKernel(pack, policyParameters) {
  const node = pack.manifest.nodes[0];
  const step = { item: { kernel_id: node.kernel_id, kernel_digest: node.kernel_digest, policy_parameters: policyParameters } };
  return runKernelNode(step);
}

// Best-effort, never fatal: a relay failure or offline environment must not
// block the check itself — mirrors anchor-client.mjs's own checkpoint path,
// which queues rather than throws on a relay failure. `helm check` has no
// journal to queue against (no daemon), so a failure here simply means the
// bundle ships without an anchors_ref entry, exactly as --no-anchor would.
async function tryAnchor(digestHex) {
  try {
    const anchor = await anchorRfc3161(digestHex);
    return [JSON.stringify(anchor)];
  } catch (err) {
    log.warn("helm check: anchoring skipped (relay unreachable or failed)", { error: String(err?.message || err) });
    return [];
  }
}

// Core entry point. opts: { packId, inputFile: raw string, noAnchor, now }.
// Returns { exitCode, report: { pack_id, input_digest, recomputed, asserted, fields, result }, bundle }.
export async function runCheck({ packId, inputFile, noAnchor = false }) {
  const pack = getPack(packId);
  const adapter = CHECK_ADAPTERS[packId];
  if (!pack || !adapter) {
    return { exitCode: EXIT.USAGE_ERROR, message: `helm check: unknown pack_id "${packId}" (not a compiled pack registered with helm check)` };
  }

  const parsed = readInputFile(inputFile);
  if (!parsed.ok) {
    return { exitCode: parsed.code, message: `helm check: ${parsed.message}` };
  }

  const policyParameters = { ...parsed.inputs };
  if (parsed.asserted !== undefined) policyParameters[adapter.assertedInputKey] = parsed.asserted;

  const validated = validateKernelInputs(pack.manifest.nodes[0].kernel_id, policyParameters);
  if (!validated.ok) {
    return { exitCode: EXIT.INSUFFICIENT_INPUT, message: `helm check: insufficient input — ${validated.error}` };
  }

  const kernelResult = await runPackKernel(pack, policyParameters);
  const outputPayload = kernelResult.artifact.output_payload;
  const inputDigest = `sha256:${await policyParametersHash({ inputs: parsed.inputs, asserted: parsed.asserted ?? null })}`;

  let resultLabel;
  let exitCode;
  if (parsed.asserted !== undefined) {
    const assertedCurrencies = currenciesOf(parsed.asserted);
    const recomputedCurrencies = currenciesOf(outputPayload[adapter.scopeCurrencyField]);
    if (assertedCurrencies.size > 0 && recomputedCurrencies.size > 0 && !intersects(assertedCurrencies, recomputedCurrencies)) {
      resultLabel = "scope_mismatch";
      exitCode = EXIT.SCOPE_DISAGREEMENT;
    }
  }
  if (exitCode === undefined) {
    const comparisonState = outputPayload[adapter.comparisonStateField];
    if (comparisonState === "matches") { resultLabel = "match"; exitCode = EXIT.MATCH; }
    else if (comparisonState === "differs") { resultLabel = "differs"; exitCode = EXIT.DIFFERS; }
    else { resultLabel = "no_assertion"; exitCode = EXIT.NO_ASSERTION; }
  }

  const fields = (outputPayload[adapter.diffField] ?? []).map((d) => ({
    name: `${d.currency ?? "?"}.${d.measure ?? "(unmatched)"}`,
    recomputed: d.recomputed_display ?? d.recomputed_minor_units,
    asserted: d.asserted_display ?? d.asserted_minor_units,
    match: d.agrees === true,
    ...(d.difference_display !== undefined ? { delta: d.difference_display } : {}),
  }));

  const report = {
    pack_id: packId,
    input_digest: inputDigest,
    recomputed: outputPayload,
    asserted: parsed.asserted ?? null,
    fields,
    result: resultLabel,
  };

  const keys = loadOrCreateKeys();
  const sealed = sealBundleObject(
    {
      kind: "check_result",
      subject: [{ name: "input_file", digest: { sha256: inputDigest.replace(/^sha256:/, "") } }],
      predicate: { pack_id: packId, comparison_result: resultLabel, exit_code: exitCode, diff: fields, recomputed: outputPayload, asserted: parsed.asserted ?? null },
    },
    keys
  );
  const anchorsRef = noAnchor ? [] : await tryAnchor(sealed.digest.replace(/^sha256:/, ""));
  const bundle = assembleBundle({
    bundleId: `helm-check-${packId}-${inputDigest.replace(/^sha256:/, "").slice(0, 16)}`,
    runId: `check-${Date.now()}`,
    workflowManifestDigest: pack.workflow_manifest_digest,
    specs: [sealed],
    anchorsRef,
    keys,
  });

  return { exitCode, report, bundle };
}
