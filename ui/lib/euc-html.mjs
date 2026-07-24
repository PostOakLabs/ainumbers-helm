// Printable-HTML renderers for HELM-P3-E12 exports. Pure template functions
// (no DOM globals) so they're unit-testable under node:test, same discipline
// as lib/to-yaml.mjs. Styling is inline + a @media print block — this is a
// standalone downloadable file, not a page mounted inside the shell, so it
// can't rely on theme.css being present.
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function docShell(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${esc(title)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; color: #111; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  h2 { font-size: 1.05rem; margin-top: 2rem; border-bottom: 1px solid #ccc; padding-bottom: 0.25rem; }
  table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
  th, td { text-align: left; padding: 0.35rem 0.5rem; border: 1px solid #ddd; vertical-align: top; font-size: 0.9rem; }
  th { background: #f4f4f4; width: 12rem; }
  code, pre { font-family: ui-monospace, monospace; font-size: 0.8rem; }
  pre { background: #f8f8f8; padding: 0.5rem; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
  .meta { color: #555; font-size: 0.85rem; }
  @media print { body { margin: 0; max-width: none; } }
</style>
</head>
<body>
${body}
</body>
</html>`;
}

export function renderEucEntryHtml(entry) {
  const kernelsRows = entry.kernels
    .map((k) => `<tr><td>${esc(k.node_id)}</td><td>${esc(k.kernel_id)}</td><td><code>${esc(k.kernel_digest)}</code></td></tr>`)
    .join("");
  const body = `
<h1>EUC register entry</h1>
<p class="meta">Generated ${esc(entry.generated_at)}</p>
<table>
  <tr><th>Workflow ID</th><td>${esc(entry.workflow_id)}</td></tr>
  <tr><th>Name</th><td>${esc(entry.name)}</td></tr>
  <tr><th>Owner</th><td>${esc(entry.owner ?? "&mdash;")}</td></tr>
  <tr><th>Purpose</th><td>${esc(entry.purpose ?? "&mdash;")}</td></tr>
  <tr><th>Control description</th><td>${esc(entry.control_description ?? "&mdash;")}</td></tr>
  <tr><th>Last validated</th><td>${esc(entry.last_validated ?? "&mdash;")}</td></tr>
  <tr><th>Workflow manifest digest</th><td><code>${esc(entry.workflow_manifest_digest)}</code></td></tr>
</table>
<h2>Kernels pinned</h2>
<table><tr><th>Node</th><th>Kernel ID</th><th>Version hash</th></tr>${kernelsRows}</table>
<h2>Declared inputs</h2>
<pre>${esc(JSON.stringify(entry.declared_inputs, null, 2))}</pre>
<h2>Declared outputs</h2>
<pre>${esc(JSON.stringify(entry.declared_outputs, null, 2))}</pre>`;
  return docShell(`EUC register entry — ${entry.name}`, body);
}

export function renderKernelCardHtml(card) {
  const vectorRows = card.test_vectors
    .map(
      (v) => `<h3>${esc(v.name)}</h3>
<table>
  <tr><th>Policy parameters</th><td><pre>${esc(JSON.stringify(v.policy_parameters, null, 2))}</pre></td></tr>
  <tr><th>Expected output</th><td><pre>${esc(JSON.stringify(v.expected_output_payload, null, 2))}</pre></td></tr>
  <tr><th>Expected execution hash</th><td><code>${esc(v.expected_execution_hash)}</code></td></tr>
</table>`
    )
    .join("");
  const body = `
<h1>Kernel validation card</h1>
<p class="meta">Generated ${esc(card.generated_at)}</p>
<table>
  <tr><th>Kernel ID</th><td>${esc(card.kernel_id)}</td></tr>
  <tr><th>Display name</th><td>${esc(card.display_name)}</td></tr>
  <tr><th>Version</th><td>${esc(card.tool_version ?? "&mdash;")}</td></tr>
  <tr><th>Source</th><td>${card.source_url ? `<a href="${esc(card.source_url)}">${esc(card.source_url)}</a>` : "&mdash;"}</td></tr>
  <tr><th>Version hash</th><td><code>${esc(card.kernel_digest)}</code></td></tr>
  <tr><th>Formula / description</th><td>${esc(card.description)}</td></tr>
</table>
<h2>Replay instructions</h2>
<p>${esc(card.replay_instructions)}</p>
<h2>Test vectors (${card.test_vectors.length})</h2>
${vectorRows}`;
  return docShell(`Kernel card — ${card.display_name}`, body);
}
