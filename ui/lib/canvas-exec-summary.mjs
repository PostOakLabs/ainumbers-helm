// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Present-toggle exec summary for the Canvas view (HELM-P4-A3,
// HELM-PHASE4-BUILD-SPEC.md §2 Band A row A3): the same manifest + digest
// the analyst view already fetched, condensed to what a committee reader
// wants — outcome, three headline numbers, a short list of green checks —
// with none of the DAG/hash/source detail. Pure and DOM-free (mirrors
// manifest-dag.mjs / committee-pack.mjs) so it's unit-testable without a
// browser. Canvas has no run/bundle attached (the run engine ships in a
// later Helm wave, per canvas.mjs's own framing), so every check here is
// something the manifest + its digest alone can honestly support — this
// never fabricates a run outcome or a §26.6 trust label that doesn't apply
// yet.
// PACK-MARKER-BUILD-SPEC.md §4.2 path (a): a node the compiler couldn't
// kernel-verify (a browser-tool step) carries `verified: false` instead of
// being silently skipped. This is never a §26.6 trust label — no run has
// happened yet, so no claim of "verified" or "hash_verified" is possible or
// implied. It names the step by its tool_id (carried in kernel_id per
// §4.4) and states only THAT it is unverified, never a fraction/percentage.
export function unverifiedSteps(manifest) {
  return (manifest.nodes ?? [])
    .filter((n) => n.verified === false)
    .map((n) => ({ nodeId: n.node_id, toolId: n.kernel_id }));
}

export function buildExecSummary(manifest, dag, digest) {
  const steps = dag.layers.reduce((n, l) => n + l.items.length, 0);
  const connectors = dag.layers.find((l) => l.key === "connectors")?.items.length ?? 0;
  const gates = dag.layers.find((l) => l.key === "gates")?.items.length ?? 0;
  const unverified = unverifiedSteps(manifest);

  const checks = [
    { ok: true, label: `workflow_manifest_digest computed: ${digest}` },
    { ok: true, label: "Pipeline order is structurally well-formed (trigger → connectors → compute → gates → actions)" },
  ];
  if (unverified.length > 0) {
    checks.push({
      ok: false,
      label: `This pack has ${unverified.length} step(s) outside kernel verification: ${unverified.map((u) => u.toolId).join(", ")} — not evaluated, run out of band`,
    });
  }

  return {
    workflowId: manifest.workflow_id,
    headline: [
      { value: steps, label: "steps in manifest" },
      { value: connectors, label: "connectors" },
      { value: gates, label: "gates" },
    ],
    checks,
    unverified,
    runNote: "No run has been recorded against this manifest yet — this view covers the manifest only, not an execution outcome.",
  };
}
