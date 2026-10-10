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
import { assertIJson, jcsStringify } from "./vendored/ocg/kernels/_hash.mjs";
import { recordCanonV1 } from "./record-canon-v1.mjs";

const SHA256REF = /^sha256:[0-9a-f]{64}$/;

// HELM-CANON-SPLIT-1 verify-class path (ruling 2026-10-01): the bound artifact
// comes from OUTSIDE helm (the site/Worker produced the three pinned digests),
// so the execution_hash is taken over the vendored RFC 8785 serializer
// (`jcsStringify`) FIRST. If the v1 (frozen pre-2026-10 helm) bytes differ —
// only possible for objects with array-index member names or a literal
// `__proto__` member — the result carries the DISTINCT verdict
// `canonicalization: "legacy-v1-divergent"`; it is never reported as a plain,
// unqualified verification. For every ordinary object the two serializers agree
// and the verdict is "rfc8785".
function verifyClassDigestHex(obj) {
  assertIJson(obj);
  const jcsHex = createHash("sha256").update(jcsStringify(obj), "utf8").digest("hex");
  const v1Hex = createHash("sha256").update(recordCanonV1(obj), "utf8").digest("hex");
  return { digest: jcsHex, canonicalization: jcsHex === v1Hex ? "rfc8785" : "legacy-v1-divergent" };
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
  const { digest: executionHash, canonicalization } = verifyClassDigestHex({ tool_ref, inputs_digest, artifact });
  return {
    trust_label: "hash_verified",
    artifact_id,
    tool_ref,
    inputs_digest,
    artifact: { ...artifact, execution_hash: executionHash },
    canonicalization,
  };
}
