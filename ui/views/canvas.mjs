// Canvas view: read-only manifest DAG + JSON/YAML side-by-side + live
// manifest_digest. Drag-to-author is a stretch goal (HELM-U2) — this ships
// view-first. The digest is computed client-side from the fetched manifest
// so it's available even when the daemon is dormant, as long as a manifest
// was cached by a prior live call.
import { fetchWithFallback, call, callText } from "../api.mjs";
import { buildDag } from "../lib/manifest-dag.mjs";
import { renderDagSvg } from "../lib/dag-svg.mjs";
import { toYaml } from "../lib/to-yaml.mjs";
import { manifestDigest } from "../lib/manifest-digest.mjs";
import { buildExecSummary } from "../lib/canvas-exec-summary.mjs";

function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function renderExecSummary(summary) {
  return `
    <section class="canvas-exec-summary" data-outcome="green">
      <p class="cp-banner-status">✓ Manifest loads and verifies structurally</p>
      <ul class="cp-headline-numbers">
        ${summary.headline.map((h) => `<li><strong>${h.value}</strong><span>${escapeHtml(h.label)}</span></li>`).join("")}
      </ul>
      <ul class="canvas-exec-checks">
        ${summary.checks.map((c) => `<li data-ok="${c.ok}">${c.ok ? "✓" : "✗"} ${escapeHtml(c.label)}</li>`).join("")}
      </ul>
      <p class="empty-state">${escapeHtml(summary.runNote)}</p>
    </section>`;
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
  const execSummary = buildExecSummary(manifest, dag, digest);

  root.innerHTML = `
    <h2>Canvas — ${escapeHtml(manifest.workflow_id)}${staleBadge}</h2>
    <div class="canvas-present-toggle" role="tablist" aria-label="Presentation mode">
      <button type="button" id="tab-present" role="tab" aria-selected="false">Present</button>
      <button type="button" id="tab-analyst" role="tab" aria-selected="true">Analyst</button>
    </div>
    <div id="canvas-present-view" hidden>${renderExecSummary(execSummary)}</div>
    <div id="canvas-analyst-view">
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
      <p class="field-row"><a href="#/run?wf=${encodeURIComponent(workflowId)}">Go to Run →</a></p>
      <h3>Spread (.helm.json)</h3>
      <p class="empty-state">Export an email-able, versioned workflow file — secrets stripped, kernels pinned by hash. Importing checks version, integrity, and kernel pins before accepting anything; any mismatch is a plain-language refusal, never a silent partial import (HELM-P3-W11).</p>
      <p class="field-row">
        <button type="button" id="export-helm-json" class="secondary">Export .helm.json</button>
        <span id="export-status" class="field-row-note" role="status"></span>
      </p>
      <p class="field-row">
        <label for="import-helm-json">Import a .helm.json file</label>
        <input type="file" id="import-helm-json" accept="application/json,.json" />
      </p>
      <p id="import-status" class="field-row-note" role="status"></p>
    </div>`;

  const presentTab = root.querySelector("#tab-present");
  const analystTab = root.querySelector("#tab-analyst");
  const presentView = root.querySelector("#canvas-present-view");
  const analystView = root.querySelector("#canvas-analyst-view");
  presentTab.addEventListener("click", () => {
    presentView.hidden = false;
    analystView.hidden = true;
    presentTab.setAttribute("aria-selected", "true");
    analystTab.setAttribute("aria-selected", "false");
  });
  analystTab.addEventListener("click", () => {
    presentView.hidden = true;
    analystView.hidden = false;
    presentTab.setAttribute("aria-selected", "false");
    analystTab.setAttribute("aria-selected", "true");
  });

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

  const exportStatus = root.querySelector("#export-status");
  root.querySelector("#export-helm-json").addEventListener("click", async () => {
    exportStatus.textContent = "Exporting…";
    const res = await callText(`/workflows/${encodeURIComponent(workflowId)}/export`, { port, token });
    if (!res.ok) {
      exportStatus.textContent = `Failed: ${typeof res.error === "string" ? res.error : res.status}`;
      return;
    }
    const blob = new Blob([res.text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${workflowId}.helm.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    exportStatus.textContent = "Downloaded.";
  });

  const importStatus = root.querySelector("#import-status");
  root.querySelector("#import-helm-json").addEventListener("change", async (ev) => {
    const file = ev.target.files?.[0];
    if (!file) return;
    importStatus.textContent = "Validating…";
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      importStatus.textContent = "Refused: not valid JSON.";
      return;
    }
    const res = await call("/workflows/import", { port, token, method: "POST", body: { export: parsed } });
    const result = res.data ?? res.error;
    if (result?.ok) {
      importStatus.textContent = `Accepted: ${result.workflow_id} (${result.kernelPins?.length ?? 0} kernel(s) pinned, all match this install).`;
    } else {
      importStatus.textContent = `Refused: ${result?.reason ?? "unknown error"}`;
    }
    ev.target.value = "";
  });
}
