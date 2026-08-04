// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Kernel execution (HELM-H7): invokes VENDORED OCG kernels from inside the H4
// run engine for "nodes" steps. D2 invariant enforced here, not just by
// convention: a manifest node's kernel_digest MUST match the vendored file's
// OWN digest (from vendored/ocg/MANIFEST.json) before the kernel runs — a
// stale or tampered pin fails loud instead of silently invoking a different
// kernel version than the one recorded in the manifest.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KERNELS } from "./vendored/ocg/kernels/index.mjs";
import { verifyBinding, verifySeal } from "./vendored/ocg/kernels/_computeproof.mjs";
import { runAttestedArtifact } from "./attested-artifact-runner.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(readFileSync(join(HERE, "vendored", "ocg", "MANIFEST.json"), "utf8"));

const KERNEL_FILE_DIGESTS = new Map(
  Object.values(MANIFEST.files)
    .filter((f) => f.path.startsWith("kernels/") && f.path.endsWith(".kernel.mjs"))
    .map((f) => [f.path.slice("kernels/".length, -".kernel.mjs".length), `sha256:${f.sha256}`])
);

export function pinnedKernelDigest(kernelId) {
  const digest = KERNEL_FILE_DIGESTS.get(kernelId);
  if (!digest) throw new Error(`kernel runner: unknown kernel_id "${kernelId}" (not in vendored MANIFEST.json)`);
  return digest;
}

// HELM-BIND-0: checks whether policy_parameters (caller-supplied or the
// manifest's own default, which feeds the SAME `?? {}` fallback below) would
// make this kernel's compute() throw — the kernel's own required-field
// checks ARE the parameter contract, so this needs no separate schema
// language. Pure and side-effect-free: never persists, never touches a run.
export function validateKernelInputs(kernelId, policyParameters) {
  const kernelModule = KERNELS[kernelId];
  if (!kernelModule) throw new Error(`kernel runner: unknown kernel_id "${kernelId}" (not in vendored registry)`);
  try {
    kernelModule.compute(policyParameters ?? {});
    return { ok: true };
  } catch (err) {
    return { ok: false, error: String(err?.message || err) };
  }
}

// Invokes the vendored kernel a run.mjs "nodes" step pins. Always returns
// trust_label "kernel_verified" (§26.6: reproducing the recorded deterministic
// kernel/version from recorded inputs IS the definition of that label) — a
// step that can't be reproduced throws rather than degrading to a weaker
// label, since §26.6 forbids collapsing/mislabeling trust claims.
export async function runKernelNode(step, { now = new Date().toISOString() } = {}) {
  const item = step.item;

  // PACK-MARKER-RUNNER-1 (§5): a node carrying `verified: false` (§4.1 schema)
  // has no vendored kernel — the compiler emitted a sentinel kernel_digest
  // that never resolves in MANIFEST.json (§4.4). Skip BEFORE any registry or
  // digest lookup: never resolve kernel_digest, never execute as a compute
  // step. The returned shape carries no `trust_label` — none of the closed
  // §26.6 set describes "not run", and inventing a 6th value is out of scope
  // — so it can never be mistaken for a kernel_verified (completed) result by
  // anything reading step_results downstream.
  if (item.verified === false) {
    return {
      execution_state: "skipped_by_design",
      node_id: item.node_id,
      kernel_id: item.kernel_id,
      reason: `verified:false — no vendored kernel for tool_id "${item.kernel_id}"; node marked, not executed`,
    };
  }

  const kernelId = item.kernel_id;
  const kernelModule = KERNELS[kernelId];
  if (!kernelModule) throw new Error(`kernel runner: kernel "${kernelId}" not found in vendored registry`);

  const pinnedDigest = pinnedKernelDigest(kernelId);
  if (item.kernel_digest && item.kernel_digest !== pinnedDigest) {
    throw new Error(
      `kernel runner: kernel_digest mismatch for "${kernelId}" — manifest pins ${item.kernel_digest}, vendored copy is ${pinnedDigest}`
    );
  }

  // HELM-BIND-2 (§3.1): run.mjs resolves a bound step's connector_inputs and
  // attaches the result as `step.resolvedParams`, keyed by feeds_param — those
  // override the node's static policy_parameters. An unbound step never gets
  // this property, so `?? {}` below is unchanged for all 230 existing packs.
  const policyParameters = { ...(item.policy_parameters ?? {}), ...(step.resolvedParams ?? {}) };

  const artifact = await kernelModule.buildArtifact(policyParameters, {
    now,
    parent_hashes: item.parent_hashes ?? [],
    parent_tool_ids: item.parent_tool_ids ?? [],
    chain_depth: item.chain_depth ?? 0,
  });

  // §18 path: when the kernel attached a compute_proof, binding + seal MUST
  // both verify before this step may complete — an unverifiable proof is a
  // hard failure of the step, not a silent downgrade.
  const computeProof = artifact.audit_signature?.compute_proof;
  let computeProofVerified = null;
  if (computeProof) {
    if (!verifyBinding(artifact, { publishedImageIds: item.compute_images ?? [] })) {
      throw new Error(`kernel runner: §18 compute_proof binding failed for "${kernelId}"`);
    }
    if (computeProof.receiptFormat === "groth16-bn254" && !verifySeal(computeProof)) {
      throw new Error(`kernel runner: §18 compute_proof seal verification failed for "${kernelId}"`);
    }
    computeProofVerified = true;
  }

  return {
    trust_label: "kernel_verified",
    kernel_id: kernelId,
    kernel_digest: pinnedDigest,
    artifact,
    compute_proof_verified: computeProofVerified,
  };
}

// stepRunner for run.mjs's executeRun(): dispatches "nodes" steps to the
// kernel, and leaves every other step kind to the caller-supplied runner
// (connectors/gates/actions are H6/Phase-2 territory, not this WU's scope).
//
// The returned function also carries a `canDispatch(step)` predicate (HELM-
// DRYRUN-PARITY-1) so run.mjs's dry-run path can ask "would a real run throw
// on this step's kind?" without invoking stepRunner — dry-run must stay
// side-effect-free, so it consults the same kind-dispatch decision instead
// of replaying it.
export function createKernelStepRunner({ otherKindsRunner = null, now } = {}) {
  function canDispatch(step) {
    if (step.kind === "nodes") return true;
    if (step.kind === "attested_artifacts") return true;
    if (!otherKindsRunner) return false;
    // HELM-BIND-3: an otherKindsRunner MAY carry its own canDispatch (the
    // connector dispatcher does) to answer per-step, not just per-kind — a
    // step naming an unknown connector/action id must predict the same
    // throw dry-run would otherwise miss. A plain runner with no such
    // predicate keeps today's per-kind-only behavior.
    if (typeof otherKindsRunner.canDispatch === "function") return otherKindsRunner.canDispatch(step);
    return true;
  }
  async function stepRunner(step, ctx) {
    if (step.kind === "nodes") return runKernelNode(step, { now });
    if (step.kind === "attested_artifacts") return runAttestedArtifact(step);
    if (otherKindsRunner) return otherKindsRunner(step, ctx);
    throw new Error(`kernel runner: no runner configured for step kind "${step.kind}" (step ${step.step_id})`);
  }
  stepRunner.canDispatch = canDispatch;
  return stepRunner;
}
