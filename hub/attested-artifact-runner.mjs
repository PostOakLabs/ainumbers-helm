// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Chainless direct-artifact binding step runner (BANK-NYDFS-HPACK-1,
// HELM-HA-BUILD-SPEC.md §3.1). An "attested_artifacts" step does NO
// execution — the tool never learns OCG hashing — it just recomputes a
// stable execution_hash from the three digests the pack's maker already
// pinned into the manifest item (tool_ref.manifest_digest, inputs_digest,
// artifact.content_digest), all of which are static per §3.1. That output
// shape, { artifact: { execution_hash } }, matches what a "nodes" step
// emits (kernel-runner.mjs runKernelNode) — which is exactly what lets
// ha-gate.mjs's subjectHashFor bind a gate to it with zero evaluator change
// (§3.2).
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";

const SHA256REF = /^sha256:[0-9a-f]{64}$/;

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

export async function runAttestedArtifact(step) {
  const item = step.item ?? {};
  const { artifact_id, tool_ref, inputs_digest, artifact } = item;
  const fields = [
    ["tool_ref.manifest_digest", tool_ref?.manifest_digest],
    ["inputs_digest", inputs_digest],
    ["artifact.content_digest", artifact?.content_digest],
  ];
  for (const [label, value] of fields) {
    if (!SHA256REF.test(value ?? "")) {
      throw new Error(`attested artifact runner: ${label} is not a well-formed sha256ref for artifact_id "${artifact_id}"`);
    }
  }
  const executionHash = jcsDigestHex({ tool_ref, inputs_digest, artifact });
  return {
    trust_label: "hash_verified",
    artifact_id,
    tool_ref,
    inputs_digest,
    artifact: { ...artifact, execution_hash: executionHash },
  };
}
