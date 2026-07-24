// Committee deck spec builder (HELM-P4-A2, HELM-PHASE4-BUILD-SPEC.md §2 Band A
// row A2): produces a plain-data, JSON-serializable slide spec for the .pptx
// committee-deck export — title slide, process-map slide, decision-table
// slide, evidence-status slide. Same input shape as committee-pack.mjs's
// buildCommitteePackHtml() (a verifyBundle().detail plus an optional workflow
// manifest), so both exports read one committee-report data model.
//
// Pure function, no DOM globals, no PptxGenJS — this module only decides
// WHAT goes on each slide. Rendering that data into an actual .pptx (which
// needs a browser: canvas to rasterize the DAG SVG, and the vendored
// PptxGenJS global) lives in committee-pptx.mjs and is not unit-tested here,
// same split as the rest of ui/ (DOM-heavy views vs. pure ui/lib/ modules).
import { buildDag } from "./manifest-dag.mjs";
import { renderDagSvg } from "./dag-svg.mjs";
import { trustLabelCounts } from "./committee-pack.mjs";

// Self-contained styling for the process-map SVG: the app's own dag-node/
// dag-edge classes live in theme.css (CSS custom properties), which do not
// exist in the standalone context this SVG gets rasterized in (an
// off-screen <img>/<canvas>, no page stylesheet attached) — so this inline
// <style> with concrete hex colors is required, not cosmetic.
const DAG_SVG_STYLE = `<style>
  .dag-col-label { fill: #666; font-size: 11px; }
  .dag-node rect { fill: #fff; stroke: #999; stroke-width: 1; }
  .dag-node text { fill: #111; font-size: 11px; }
  .dag-edge { stroke: #999; stroke-width: 1.5; }
  .dag-arrowhead { fill: #999; }
</style>`;

function selfContainedDagSvg(manifest) {
  const svg = renderDagSvg(buildDag(manifest));
  return svg.replace("<defs>", `${DAG_SVG_STYLE}<defs>`);
}

function decisionRows(entries) {
  return entries.map((e) => [
    e.predicate?.step_id ?? e.predicate?.connector_id ?? e.predicate?.run_id ?? "—",
    e.kind,
    e.trust_label,
    e.valid === false ? "✗ failed" : "✓ verified",
  ]);
}

// meta: { entity, period, preparer } — same committee-report identity fields
// buildCommitteePackHtml() takes; caller supplies them, never derived/guessed.
export function buildCommitteeDeckSpec({ bundle, entries, checkpoints, manifest, manifestDigest, generatedAt, meta = {} }) {
  const predicate = bundle.manifest.predicate;
  const counts = trustLabelCounts(entries);
  const failedCount = entries.filter((e) => e.valid === false).length + checkpoints.filter((c) => c.valid === false).length;
  const overallOk = failedCount === 0;

  return {
    title: {
      bundleId: predicate.bundle_id,
      entity: meta.entity ?? "—",
      period: meta.period ?? "—",
      preparer: meta.preparer ?? "—",
      generatedAt: generatedAt ?? "—",
      versionDigest: manifestDigest ?? predicate.workflow_manifest_digest ?? "—",
    },
    processMap: manifest
      ? { available: true, svg: selfContainedDagSvg(manifest) }
      : { available: false, note: "Process map not shown — no workflow manifest is attached to this export (bundle-only export carries just its digest, SPEC.md §26.3)." },
    decisionTable: {
      headers: ["Step", "Kind", "Trust label", "Result"],
      rows: decisionRows(entries),
    },
    evidenceStatus: {
      overallOk,
      headline: [
        { value: entries.length, label: "steps recorded" },
        { value: checkpoints.length, label: "checkpoints" },
        { value: failedCount, label: "failed checks" },
      ],
      runDate: predicate.run_id ?? generatedAt ?? "—",
      trustCounts: Array.from(counts.entries()).map(([label, n]) => ({ label, n })),
    },
  };
}
