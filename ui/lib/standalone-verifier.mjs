// Single-file, zero-install offline evidence-bundle verifier (HELM-P3-V9,
// SPEC.md §26.7-§26.8, HELM-PHASE3-BUILD-SPEC.md §3 item 1). Embedded in every
// bundle.zip export (see hub/bundle.mjs's exportBundleZip): a colleague opens
// this ONE HTML file from file:// with the bundle+identity baked in, no
// server, no daemon, no network. Pure template function — no DOM globals, so
// it's unit-testable under node:test — mirrors ui/views/verify.mjs's render
// logic (trust labels, copy fence) but drives itself from embedded data
// instead of file-picker inputs, since there is no shell around it here.
import { VERIFIER_RUNTIME_JS } from "./standalone-verifier-runtime.gen.mjs";

const TRUST_LABEL_COPY = {
  hash_verified: "The artifact is unchanged relative to its stated preimage. Nothing here says the preimage itself was true.",
  kernel_verified: "A recorded deterministic kernel reproduced the recorded result from the recorded inputs. This does NOT mean the inputs were accurate — only that the computation over them is reproducible.",
  connector_asserted: "An authorized connector reported this payload at a point in time. There is NO claim that the payload's contents are true.",
  human_attested: "An identified authority reviewed, approved, or overrode a defined evidence package. This records a decision, not a guarantee the decision was correct.",
  external_ack_captured: "An external service returned this exact reference or receipt. There is NO claim about what that service did internally.",
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Bundle/identity JSON travels inside a non-executing <script type="application/json">
// tag rather than interpolated into the driver script directly, so a
// hostile digest/id string in the bundle can't break out of a JS string
// literal into the surrounding script.
function dataScript(id, obj) {
  return `<script type="application/json" id="${id}">${JSON.stringify(obj).replace(/</g, "\\u003c")}</script>`;
}

const STYLE = `
:root { color-scheme: light dark; --fg:#111; --bg:#fff; --card:#f6f6f7; --border:#ddd; --ok:#1a7f37; --bad:#c0341d; }
@media (prefers-color-scheme: dark) { :root { --fg:#e8e8e8; --bg:#15161a; --card:#1e2026; --border:#33353c; --ok:#3fb950; --bad:#f85149; } }
body { font-family: system-ui, sans-serif; max-width: 56rem; margin: 2rem auto; padding: 0 1rem; color: var(--fg); background: var(--bg); }
h1 { font-size: 1.4rem; } h2 { font-size: 1.1rem; margin-top: 2rem; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin: 1rem 0; }
.summary[data-ok="true"] { color: var(--ok); font-weight: 600; }
.summary[data-ok="false"] { color: var(--bad); font-weight: 600; }
.entry { border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem; margin: 0.5rem 0; }
.entry[data-ok="false"] { border-color: var(--bad); }
.badge { display: inline-block; font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 3px; border: 1px solid var(--border); margin-right: 0.35rem; }
code { font-family: ui-monospace, monospace; font-size: 0.85em; word-break: break-all; }
dl.fence div { margin-bottom: 0.6rem; }
dt { font-weight: 600; }
`;

export function buildStandaloneVerifierHtml({ bundle, publicKeys }) {
  const body = `<h1>Helm evidence bundle — offline verifier</h1>
<p>This page verifies entirely inside this browser tab. Nothing here is uploaded, and nothing here requires a server, a daemon, or a network connection — open it from a saved file (<code>file://</code>) and it still works.</p>

<section class="card" aria-labelledby="what-checked">
  <h2 id="what-checked">What this checks — and what it does not</h2>
  <dl class="fence">
    <div><dt>✓ Checked</dt><dd>Every object's DSSE envelope: Ed25519 signature (required) and ML-DSA-44 signature (checked whenever present). Every entry's digest, kind, and trust label match the signed manifest exactly. Redaction: no secret-shaped fields are present. Each checkpoint's declared running-hash state is internally self-consistent. RFC 3161 anchors: the token's message imprint is bound to the checkpoint it claims to cover.</dd></div>
    <div><dt>✗ NOT checked</dt><dd>Whether the underlying real-world event is true. The TSA certificate's chain of trust to a root authority. Whether an OpenTimestamps anchor has been upgraded to a Bitcoin block proof. Whether this matches a live daemon's journal — this page has none.</dd></div>
  </dl>
</section>

<section id="result" class="card" aria-live="polite"><p>Verifying…</p></section>

${dataScript("bundle-data", bundle)}
${dataScript("keys-data", publicKeys)}
<script>
${VERIFIER_RUNTIME_JS}
const TRUST_LABEL_COPY = ${JSON.stringify(TRUST_LABEL_COPY)};
function esc(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function trustBadge(label) {
  const known = label in TRUST_LABEL_COPY;
  return '<span class="badge" title="' + esc(known ? TRUST_LABEL_COPY[label] : "Not one of the five §26.6 labels — a nonconformant producer, never treated as verified.") + '">' + esc(label) + '</span>';
}
function statusIcon(ok) { return ok ? "✓" : (ok === false ? "✗" : "?"); }
async function run() {
  const bundle = JSON.parse(document.getElementById("bundle-data").textContent);
  const publicKeys = JSON.parse(document.getElementById("keys-data").textContent);
  const resultEl = document.getElementById("result");
  let result;
  try {
    result = await verifyBundle(bundle, publicKeys);
  } catch (err) {
    resultEl.innerHTML = '<p class="summary" data-ok="false">✗ Could not verify: ' + esc(err.message) + '</p>';
    return;
  }
  const entriesHtml = result.detail.entries.length
    ? result.detail.entries.map(e => '<div class="entry" data-ok="' + e.valid + '">' + statusIcon(e.valid) + ' ' + esc(e.kind) + ' ' + trustBadge(e.trust_label) + ' <code>' + esc(e.digest) + '</code></div>').join("")
    : '<p>No entries.</p>';
  const checkpointsHtml = result.detail.checkpoints.length
    ? result.detail.checkpoints.map(cp => '<div class="entry" data-ok="' + cp.valid + '">' + statusIcon(cp.valid) + ' checkpoint #' + cp.checkpointSeq + ' <code>' + esc(cp.digest) + '</code>' + (cp.reason ? ' <em>' + esc(cp.reason) + '</em>' : '') + '</div>').join("")
    : '<p>No checkpoints in this bundle.</p>';
  resultEl.innerHTML =
    '<p class="summary" data-ok="' + result.valid + '">' + (result.valid ? '✓ Bundle verifies.' : '✗ Bundle FAILS verification (' + result.reasons.length + ' reason' + (result.reasons.length === 1 ? '' : 's') + ').') + '</p>' +
    (result.reasons.length ? '<ul>' + result.reasons.map(r => '<li>' + esc(r) + '</li>').join('') + '</ul>' : '') +
    '<h2>Objects</h2>' + entriesHtml +
    '<h2>Checkpoints</h2>' + checkpointsHtml;
}
run();
</script>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Helm evidence bundle — offline verifier</title>
<style>${STYLE}</style>
</head>
<body>
${body}
</body>
</html>`;
}

export { TRUST_LABEL_COPY, esc };
