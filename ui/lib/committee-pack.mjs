// Committee Pack export (HELM-P4-A1, HELM-PHASE4-BUILD-SPEC.md §2 Band A row A1):
// an ISAE-3000/SOC-2-shaped, print-CSS HTML report for the recurring
// template->run->export loop a committee/BA reads without explanation.
// Same "print-CSS is the PDF" doctrine as auditor-pdf.mjs (HELM-P3-V9) — no
// binary PDF generation, no paged.js dependency; every browser's native
// "Print to PDF" turns this into a real, losslessly-paginated PDF because
// the stylesheet already carries a dedicated @media print block.
//
// Layered structure, cheapest-read-first (p1 outcome banner -> process map +
// decision table -> collapsible full-detail appendix): a committee reads
// page 1 and stops; an auditor expands the appendix. Zero dev chrome — no
// raw JSON is rendered above the appendix.
//
// Pure template function (no DOM globals, no crypto): callers pass
// already-computed verification detail (ui/lib/verify-bundle.mjs's
// verifyBundle().detail, the same shape auditor-pdf.mjs consumes) plus an
// OPTIONAL workflow manifest for the process map — a bundle carries only
// workflow_manifest_digest, not the manifest itself (SPEC.md §26.3), so a
// caller with just a bundle.json (no paired .helm.json export) gets an
// honest "not attached" note instead of a fabricated diagram.
import { buildDag } from "./manifest-dag.mjs";
import { renderDagSvg } from "./dag-svg.mjs";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const TRUST_LABELS_ORDER = [
  "hash_verified",
  "kernel_verified",
  "connector_asserted",
  "human_attested",
  "external_ack_captured",
];

function trustLabelCounts(entries) {
  const counts = new Map(TRUST_LABELS_ORDER.map((l) => [l, 0]));
  for (const e of entries) {
    counts.set(e.trust_label, (counts.get(e.trust_label) ?? 0) + 1);
  }
  return counts;
}

function renderOutcomeBanner({ overallOk, headline, runDate, counts }) {
  const countRows = Array.from(counts.entries())
    .map(([label, n]) => `<li><span class="cp-trust-badge" data-label="${esc(label)}">${esc(label)}</span> <strong>${n}</strong></li>`)
    .join("");
  return `
<section class="cp-banner" data-outcome="${overallOk ? "green" : "amber"}">
  <p class="cp-banner-status">${overallOk ? "✓ Verifies clean" : "△ Needs review"}</p>
  <ul class="cp-headline-numbers">
    ${headline.map((h) => `<li><strong>${esc(h.value)}</strong><span>${esc(h.label)}</span></li>`).join("")}
  </ul>
  <p class="cp-run-date">Run date: ${esc(runDate)}</p>
  <h3>Trust-label counts</h3>
  <ul class="cp-trust-counts">${countRows}</ul>
</section>`;
}

function renderProcessMap(manifest) {
  if (!manifest) {
    return `<p class="cp-unavail">Process map not shown — no workflow manifest is attached to this export (bundle-only export carries just its digest, SPEC.md §26.3). Pair this bundle with its .helm.json workflow export to include the diagram.</p>`;
  }
  return renderDagSvg(buildDag(manifest));
}

function renderDecisionTable(entries) {
  if (!entries.length) return `<p class="cp-unavail">No steps recorded.</p>`;
  const rows = entries
    .map(
      (e) => `<tr>
        <td>${esc(e.predicate?.step_id ?? e.predicate?.connector_id ?? e.predicate?.run_id ?? "—")}</td>
        <td>${esc(e.kind)}</td>
        <td><span class="cp-trust-badge" data-label="${esc(e.trust_label)}">${esc(e.trust_label)}</span></td>
        <td>${e.valid === false ? "✗ failed" : "✓ verified"}</td>
      </tr>`
    )
    .join("");
  return `<table class="cp-decision-table">
    <thead><tr><th>Step</th><th>Kind</th><th>Trust label</th><th>Result</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;
}

function renderAppendixEntry(entry) {
  const sigRows = (entry.envelope?.signatures ?? [])
    .map((s) => `<li><code>${esc(s.alg)}</code> — keyid <code>${esc(s.keyid)}</code></li>`)
    .join("");
  return `<div class="cp-entry">
    <h4>${esc(entry.kind)} <span class="cp-trust-badge" data-label="${esc(entry.trust_label)}">${esc(entry.trust_label)}</span></h4>
    <p class="cp-digest">Digest: <code>${esc(entry.digest)}</code></p>
    <ul class="cp-sig-list">${sigRows || "<li>none</li>"}</ul>
  </div>`;
}

function renderAppendixCheckpoint(cp) {
  const anchors = (cp.predicate?.anchors ?? [])
    .map((a) => `<li>${esc(a.type)}${a.binding?.checked ? ` — ${a.binding.bound ? "bound" : "NOT bound"}` : ""}</li>`)
    .join("");
  return `<div class="cp-entry">
    <h4>Checkpoint #${esc(cp.checkpointSeq)}</h4>
    <p class="cp-digest">Journal root digest: <code>${esc(cp.digest ?? cp.predicate?.journal_root_digest ?? "")}</code></p>
    <ul class="cp-sig-list">${anchors || "<li>no anchors</li>"}</ul>
  </div>`;
}

// Art.12 journal: the append-only per-step journal entries a checkpoint's
// journal_root_digest commits over (ui/lib/browser-journal.mjs writes these
// at run time) — optional, since a bundle alone does not carry the raw
// journal, only its committed digest per checkpoint.
function renderArt12Journal(journalEntries) {
  if (!journalEntries?.length) {
    return `<p class="cp-unavail">Art.12 journal not attached to this export — only the committed journal_root_digest per checkpoint is carried by the bundle itself.</p>`;
  }
  const rows = journalEntries
    .map((j) => `<tr><td><code>${esc(j.seq)}</code></td><td>${esc(j.recorded_at)}</td><td><code>${esc(j.digest)}</code></td></tr>`)
    .join("");
  return `<table class="cp-decision-table"><thead><tr><th>Seq</th><th>Recorded</th><th>Digest</th></tr></thead><tbody>${rows}</tbody></table>`;
}

const STYLE = `
:root { color-scheme: light dark; --fg:#111; --bg:#fff; --card:#f6f6f7; --border:#ccc; --green:#1a7f37; --amber:#9a6700; }
@media (prefers-color-scheme: dark) { :root { --fg:#e8e8e8; --bg:#15161a; --card:#1e2026; --border:#3a3c44; --green:#4cbb6d; --amber:#e0a530; } }
body { font-family: system-ui, sans-serif; max-width: 58rem; margin: 2rem auto; padding: 0 1rem; color: var(--fg); background: var(--bg); }
.cp-title-block { border-bottom: 2px solid var(--border); padding-bottom: 0.75rem; margin-bottom: 1rem; }
.cp-title-block h1 { font-size: 1.5rem; margin: 0 0 0.25rem; }
.cp-title-meta { font-size: 0.85rem; color: #888; }
.cp-title-meta table { border: none; width: auto; }
.cp-title-meta th, .cp-title-meta td { border: none; padding: 0.1rem 0.6rem 0.1rem 0; text-align: left; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.25rem; }
.cp-banner { border: 2px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }
.cp-banner[data-outcome="green"] { border-color: var(--green); }
.cp-banner[data-outcome="amber"] { border-color: var(--amber); }
.cp-banner-status { font-size: 1.2rem; font-weight: 600; margin: 0 0 0.5rem; }
.cp-banner[data-outcome="green"] .cp-banner-status { color: var(--green); }
.cp-banner[data-outcome="amber"] .cp-banner-status { color: var(--amber); }
.cp-headline-numbers { display: flex; gap: 2rem; list-style: none; padding: 0; margin: 0.5rem 0; }
.cp-headline-numbers li { display: flex; flex-direction: column; }
.cp-headline-numbers strong { font-size: 1.6rem; }
.cp-headline-numbers span { font-size: 0.75rem; color: #888; }
.cp-trust-counts { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.75rem; }
table { border-collapse: collapse; width: 100%; margin: 0.4rem 0; }
th, td { text-align: left; padding: 0.3rem 0.5rem; border: 1px solid var(--border); font-size: 0.85rem; vertical-align: top; }
th { background: var(--card); }
.cp-decision-table td, .cp-decision-table th { font-size: 0.82rem; }
code { font-family: ui-monospace, monospace; font-size: 0.82em; word-break: break-all; }
.cp-trust-badge { display: inline-block; font-size: 0.7rem; padding: 0.05rem 0.4rem; border: 1px solid var(--border); border-radius: 3px; background: var(--card); }
.cp-entry { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 0.9rem; margin: 0.5rem 0; }
.cp-digest { font-size: 0.85rem; }
.cp-unavail { color: #888; font-style: italic; font-size: 0.85rem; }
.cp-attestation { margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem; }
.cp-sign-line { display: inline-block; width: 16rem; border-bottom: 1px solid var(--fg); margin: 1.5rem 1rem 0.25rem 0; }
.cp-page-map svg { max-width: 100%; height: auto; }
details.cp-appendix { margin-top: 1.5rem; }
details.cp-appendix > summary { cursor: pointer; font-weight: 600; padding: 0.4rem 0; }
@media print {
  body { margin: 0; max-width: none; color: #000; background: #fff; }
  .cp-entry, table, th { background: #fff; }
  details.cp-appendix { break-before: page; }
  details.cp-appendix[open] > summary { break-after: avoid; }
  .cp-page-map { break-inside: avoid; }
}
`;

// meta: { entity, period, preparer } — committee-report identity fields a
// bundle has no concept of; caller supplies them (e.g. from the workflow's
// UI-configured name + the operator's own identity), never derived/guessed.
export function buildCommitteePackHtml({ bundle, entries, checkpoints, manifest, journalEntries, manifestDigest, generatedAt, meta = {} }) {
  const predicate = bundle.manifest.predicate;
  const counts = trustLabelCounts(entries);
  const failedCount = entries.filter((e) => e.valid === false).length + checkpoints.filter((c) => c.valid === false).length;
  const overallOk = failedCount === 0;
  const headline = [
    { value: entries.length, label: "steps recorded" },
    { value: checkpoints.length, label: "checkpoints" },
    { value: failedCount, label: "failed checks" },
  ];

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Committee Pack — ${esc(predicate.bundle_id)}</title>
<style>${STYLE}</style>
</head>
<body>
<header class="cp-title-block">
  <h1>Committee Pack</h1>
  <table class="cp-title-meta">
    <tr><th>Entity</th><td>${esc(meta.entity ?? "—")}</td><th>Period</th><td>${esc(meta.period ?? "—")}</td></tr>
    <tr><th>Preparer</th><td>${esc(meta.preparer ?? "—")}</td><th>Date</th><td>${esc(generatedAt ?? "—")}</td></tr>
    <tr><th>Version / digest</th><td colspan="3"><code>${esc(manifestDigest ?? predicate.workflow_manifest_digest ?? "—")}</code></td></tr>
  </table>
</header>

${renderOutcomeBanner({ overallOk, headline, runDate: predicate.run_id ?? generatedAt ?? "—", counts })}

<h2>Process map</h2>
<div class="cp-page-map">${renderProcessMap(manifest)}</div>

<h2>Decision table</h2>
${renderDecisionTable(entries)}

<details class="cp-appendix">
  <summary>Full appendix — DAG, hashes, DSSE/RFC3161 chain, Art.12 journal (${entries.length + checkpoints.length} items)</summary>

  <h3>Kernel outputs &amp; connector activity</h3>
  ${entries.map(renderAppendixEntry).join("") || `<p class="cp-unavail">No entries.</p>`}

  <h3>Checkpoints &amp; timestamp anchors</h3>
  ${checkpoints.map(renderAppendixCheckpoint).join("") || `<p class="cp-unavail">No checkpoints in this bundle.</p>`}

  <h3>Art.12 journal</h3>
  ${renderArt12Journal(journalEntries)}
</details>

<section class="cp-attestation">
  <h2>Attestation</h2>
  <p>This report was generated from a signed evidence bundle. The appendix above verifies independently against <code>bundle.json</code> using the offline verifier shipped in the same export — re-verification does not depend on this document or its author.</p>
  <p><span class="cp-sign-line"></span> Reviewed by / date</p>
  <p><span class="cp-sign-line"></span> Approved by / date</p>
</section>
</body>
</html>`;
}
