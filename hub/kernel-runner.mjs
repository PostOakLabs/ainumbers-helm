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

// Invokes the vendored kernel a run.mjs "nodes" step pins. Always returns
// trust_label "kernel_verified" (§26.6: reproducing the recorded deterministic
// kernel/version from recorded inputs IS the definition of that label) — a
// step that can't be reproduced throws rather than degrading to a weaker
// label, since §26.6 forbids collapsing/mislabeling trust claims.
export async function runKernelNode(step, { now = new Date().toISOString() } = {}) {
  const item = step.item;
  const kernelId = item.kernel_id;
  const kernelModule = KERNELS[kernelId];
  if (!kernelModule) throw new Error(`kernel runner: kernel "${kernelId}" not found in vendored registry`);

  const pinnedDigest = pinnedKernelDigest(kernelId);
  if (item.kernel_digest && item.kernel_digest !== pinnedDigest) {
    throw new Error(
      `kernel runner: kernel_digest mismatch for "${kernelId}" — manifest pins ${item.kernel_digest}, vendored copy is ${pinnedDigest}`
    );
  }

  const artifact = await kernelModule.buildArtifact(item.policy_parameters ?? {}, {
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
export function createKernelStepRunner({ otherKindsRunner = null, now } = {}) {
  return async function stepRunner(step, ctx) {
    if (step.kind === "nodes") return runKernelNode(step, { now });
    if (otherKindsRunner) return otherKindsRunner(step, ctx);
    throw new Error(`kernel runner: no runner configured for step kind "${step.kind}" (step ${step.step_id})`);
  };
}
