// Canvas view: read-only manifest DAG + JSON/YAML side-by-side + live
// manifest_digest. Drag-to-author is a stretch goal (HELM-U2) — this ships
// view-first. The digest is computed client-side from the fetched manifest
// so it's available even when the daemon is dormant, as long as a manifest
// was cached by a prior live call.
import { fetchWithFallback } from "../api.mjs";
import { buildDag } from "../lib/manifest-dag.mjs";
import { renderDagSvg } from "../lib/dag-svg.mjs";
import { toYaml } from "../lib/to-yaml.mjs";
import { manifestDigest } from "../lib/manifest-digest.mjs";

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function frameFor(state, workflowId) {
  if (state === "unavailable") {
    return `<p class="unavailable-state">Manifests aren't served by this daemon yet — the run engine ships in a later Helm wave.</p>`;
  }
  return `<p class="empty-state">Can't fetch the manifest for <code>${workflowId}</code>. Start helmd and open its pairing link, or pick a pack from Choose.</p>`;
}

export async function renderCanvas(root, { port, token, params }) {
  const workflowId = params?.get("wf");
  if (!workflowId) {
    root.innerHTML = `<p class="empty-state">No workflow selected. Pick one from <a href="#/choose">Choose</a>.</p>`;
    return;
  }

  root.innerHTML = `<p aria-live="polite">Loading manifest for ${workflowId}…</p>`;
  const result = await fetchWithFallback(`/workflow-manifest?workflow_id=${encodeURIComponent(workflowId)}`, { port, token });

  if (result.state === "unavailable" || result.state === "missing") {
    root.innerHTML = frameFor(result.state, workflowId);
    return;
  }

  const manifest = result.data;
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";
  const dag = buildDag(manifest);
  const svg = renderDagSvg(dag);
  const digest = await manifestDigest(manifest);

  root.innerHTML = `
    <h2>Canvas — ${escapeHtml(manifest.workflow_id)}${staleBadge}</h2>
    <p class="field-row">
      <span>workflow_manifest_digest</span>
      <code id="canvas-digest">${digest}</code>
    </p>
    <p class="empty-state">Read-only graph, derived from manifest order (trigger → connectors → compute → gates → actions). No edges are stored in the manifest itself.</p>
    <div class="dag-frame" role="list" aria-label="Manifest graph">${svg}</div>
    <div class="canvas-source">
      <div class="canvas-source-toggle" role="tablist" aria-label="Manifest source format">
        <button type="button" id="tab-json" role="tab" aria-selected="true">JSON</button>
        <button type="button" id="tab-yaml" role="tab" aria-selected="false">YAML</button>
      </div>
      <pre id="source-json">${escapeHtml(JSON.stringify(manifest, null, 2))}</pre>
      <pre id="source-yaml" hidden>${escapeHtml(toYaml(manifest))}</pre>
    </div>
    <p class="field-row"><a href="#/run?wf=${encodeURIComponent(workflowId)}">Go to Run →</a></p>`;

  const jsonTab = root.querySelector("#tab-json");
  const yamlTab = root.querySelector("#tab-yaml");
  const jsonEl = root.querySelector("#source-json");
  const yamlEl = root.querySelector("#source-yaml");
  jsonTab.addEventListener("click", () => {
    jsonEl.hidden = false;
    yamlEl.hidden = true;
    jsonTab.setAttribute("aria-selected", "true");
    yamlTab.setAttribute("aria-selected", "false");
  });
  yamlTab.addEventListener("click", () => {
    jsonEl.hidden = true;
    yamlEl.hidden = false;
    jsonTab.setAttribute("aria-selected", "false");
    yamlTab.setAttribute("aria-selected", "true");
  });
}
