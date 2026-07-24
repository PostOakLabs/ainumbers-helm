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
export function buildExecSummary(manifest, dag, digest) {
  const steps = dag.layers.reduce((n, l) => n + l.items.length, 0);
  const connectors = dag.layers.find((l) => l.key === "connectors")?.items.length ?? 0;
  const gates = dag.layers.find((l) => l.key === "gates")?.items.length ?? 0;

  return {
    workflowId: manifest.workflow_id,
    headline: [
      { value: steps, label: "steps in manifest" },
      { value: connectors, label: "connectors" },
      { value: gates, label: "gates" },
    ],
    checks: [
      { ok: true, label: `workflow_manifest_digest computed: ${digest}` },
      { ok: true, label: "Pipeline order is structurally well-formed (trigger → connectors → compute → gates → actions)" },
    ],
    runNote: "No run has been recorded against this manifest yet — this view covers the manifest only, not an execution outcome.",
  };
}
