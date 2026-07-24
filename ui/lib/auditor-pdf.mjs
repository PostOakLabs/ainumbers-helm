// Human-readable, printable rendering of an evidence bundle (HELM-P3-V9,
// HELM-PHASE3-BUILD-SPEC.md §3 item 3: "paper is the audit currency").
// Print-CSS HTML, not a binary PDF — acceptable per the row's own contract;
// every browser's native "Print to PDF" turns this into a real PDF losslessly
// since the stylesheet already carries a dedicated @media print block. Pure
// template function (no DOM globals, no crypto) — callers pass already-
// computed verification detail (see hub/bundle.mjs's exportBundleZip) rather
// than this module re-deriving it, so it stays synchronous and testable.
import { QRCODEGEN_JS } from "./qrcodegen-runtime.gen.mjs";

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const KNOWN_PREDICATE_FIELDS = [
  "run_id", "step_id", "state", "output_digest",
  "connector_id", "connector_version", "operation", "endpoint_host", "payload_digest", "requested_at",
  "period_start", "period_end", "reference_db_version",
];

function isoUtcNote(value) {
  return typeof value === "string" && /Z$/.test(value) ? `${esc(value)} <span class="tz">(UTC, ISO-8601)</span>` : esc(value);
}

function renderKnownFields(predicate) {
  const rows = KNOWN_PREDICATE_FIELDS.filter((k) => k in predicate).map(
    (k) => `<tr><th>${esc(k)}</th><td>${/_at$|^period_/.test(k) ? isoUtcNote(predicate[k]) : `<code>${esc(JSON.stringify(predicate[k]))}</code>`}</td></tr>`
  );
  return rows.length ? `<table>${rows.join("")}</table>` : "";
}

function renderEntry(entry) {
  const sigRows = (entry.envelope?.signatures ?? [])
    .map((s) => `<li><code>${esc(s.alg)}</code> — keyid <code>${esc(s.keyid)}</code></li>`)
    .join("");
  return `
<div class="entry">
  <h3>${esc(entry.kind)} <span class="badge">${esc(entry.trust_label)}</span></h3>
  <p class="digest">Digest: <code>${esc(entry.digest)}</code></p>
  ${entry.predicate ? renderKnownFields(entry.predicate) : `<p class="unavail">Not independently verified — object omitted from this bundle or failed verification; predicate not shown.</p>`}
  <h4>Signatures</h4>
  <ul class="sig-list">${sigRows || "<li>none</li>"}</ul>
</div>`;
}

function renderCheckpoint(cp) {
  const anchors = (cp.predicate?.anchors ?? [])
    .map((a) => {
      // R15-F5/P3-D4: queued/skipped is a neutral, expected state (relay
      // unreachable/blocked at checkpoint time) — render it plainly, not as
      // a missing/failed anchor.
      if (a.type === "queued" || a.type === "skipped") {
        const rows = [`<tr><th>Reason</th><td>${esc(a.reason)}</td></tr>`, `<tr><th>Relay</th><td><code>${esc(a.relay_url)}</code></td></tr>`];
        if (a.recorded_at) rows.push(`<tr><th>Recorded</th><td>${isoUtcNote(a.recorded_at)}</td></tr>`);
        return `<div class="anchor"><h4>Anchoring ${esc(a.type)}</h4><table>${rows.join("")}</table></div>`;
      }
      const b = a.binding;
      const rows = [];
      if (b?.genTime) rows.push(`<tr><th>TSA time</th><td>${isoUtcNote(b.genTime)}</td></tr>`);
      if (b?.policyOid) rows.push(`<tr><th>Policy OID</th><td><code>${esc(b.policyOid)}</code></td></tr>`);
      rows.push(`<tr><th>Bound to this checkpoint</th><td>${b?.checked ? (b.bound ? "yes" : "NO — not bound") : "not structurally checkable"}</td></tr>`);
      return `<div class="anchor"><h4>Anchor: ${esc(a.type)}</h4><table>${rows.join("")}</table></div>`;
    })
    .join("");
  return `
<div class="entry">
  <h3>Checkpoint #${esc(cp.checkpointSeq)}</h3>
  <p class="digest">Journal root digest: <code>${esc(cp.digest ?? cp.predicate?.journal_root_digest ?? "")}</code></p>
  ${anchors || "<p class=\"unavail\">No anchors on this checkpoint.</p>"}
</div>`;
}

const STYLE = `
:root { color-scheme: light dark; --fg:#111; --bg:#fff; --card:#f6f6f7; --border:#ccc; }
@media (prefers-color-scheme: dark) { :root { --fg:#e8e8e8; --bg:#15161a; --card:#1e2026; --border:#3a3c44; } }
body { font-family: system-ui, sans-serif; max-width: 54rem; margin: 2rem auto; padding: 0 1rem; color: var(--fg); background: var(--bg); }
h1 { font-size: 1.4rem; margin-bottom: 0.1rem; } h2 { font-size: 1.05rem; margin-top: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 0.25rem; }
.meta { color: #888; font-size: 0.85rem; }
table { border-collapse: collapse; width: 100%; margin: 0.4rem 0; }
th, td { text-align: left; padding: 0.3rem 0.5rem; border: 1px solid var(--border); font-size: 0.85rem; vertical-align: top; }
th { background: var(--card); width: 11rem; }
code { font-family: ui-monospace, monospace; font-size: 0.82em; word-break: break-all; }
.badge { display: inline-block; font-size: 0.7rem; padding: 0.05rem 0.4rem; border: 1px solid var(--border); border-radius: 3px; }
.entry { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0; }
.digest { font-size: 0.85rem; }
.unavail { color: #888; font-style: italic; font-size: 0.85rem; }
.tz { color: #888; font-size: 0.8em; }
.qr-block { display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap; }
.qr-block svg { width: 9rem; height: 9rem; background: #fff; border-radius: 4px; }
@media print { body { margin: 0; max-width: none; color: #000; background: #fff; } .entry, table, th { background: #fff; } a[href]::after { content: ""; } }
`;

// entries/checkpoints: pre-computed detail (e.g. from ui/lib/verify-bundle.mjs's
// verifyBundle().detail, or the hub sync equivalent) — kind/trust_label/digest/
// predicate per object, checkpointSeq/digest/predicate per checkpoint (each
// checkpoint's anchors[] may carry a `binding` field, the structural
// verifyAnchorBinding() result, attached by the caller).
export function buildAuditorHtml({ bundle, entries, checkpoints, manifestDigest, generatedAt }) {
  const predicate = bundle.manifest.predicate;
  const qrJs = manifestDigest ? `qrcodegen.QrCode.encodeText(${JSON.stringify(manifestDigest)}, qrcodegen.QrCode.Ecc.MEDIUM).toSvgString(4)` : null;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Evidence bundle — ${esc(predicate.bundle_id)}</title>
<style>${STYLE}</style>
</head>
<body>
<h1>Evidence bundle audit record</h1>
<p class="meta">Generated ${esc(generatedAt ?? "")}</p>

<table>
  <tr><th>Bundle ID</th><td><code>${esc(predicate.bundle_id)}</code></td></tr>
  <tr><th>Run ID</th><td><code>${esc(predicate.run_id)}</code></td></tr>
  <tr><th>Workflow manifest digest</th><td><code>${esc(predicate.workflow_manifest_digest)}</code></td></tr>
  <tr><th>Redaction profile</th><td>${esc(predicate.redaction_profile)}</td></tr>
</table>

${manifestDigest ? `
<h2>Re-verification</h2>
<div class="qr-block">
  <div id="qr-target"></div>
  <div><p>Scan, or paste this digest into the offline verifier (verify.html, shipped in the same bundle.zip) alongside the bundle file to re-check this record independently.</p>
  <p><code>${esc(manifestDigest)}</code></p></div>
</div>` : ""}

<h2>Kernel outputs &amp; connector activity (${entries.length})</h2>
${entries.map(renderEntry).join("") || "<p class=\"unavail\">No entries.</p>"}

<h2>Checkpoints &amp; timestamp anchors (${checkpoints.length})</h2>
${checkpoints.map(renderCheckpoint).join("") || "<p class=\"unavail\">No checkpoints in this bundle.</p>"}

${qrJs ? `<script>${QRCODEGEN_JS}
document.getElementById("qr-target").innerHTML = ${qrJs};
</script>` : ""}
</body>
</html>`;
}
