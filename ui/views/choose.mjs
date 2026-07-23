// Choose view: an outcome-oriented list of workflow packs, NOT a raw
// inventory of every manifest on disk. Selecting one opens Canvas
// (read-only DAG first; authoring is a stretch goal per HELM-U2).
import { fetchWithFallback } from "../api.mjs";

function packCard(pack) {
  const outcome = pack.outcome ?? "";
  return `
    <article class="card" aria-labelledby="pack-${pack.workflow_id}">
      <h3 id="pack-${pack.workflow_id}">${pack.name ?? pack.workflow_id}</h3>
      <p class="field-row-note">${outcome}</p>
      <p class="field-row"><span>Status</span><span>${pack.status ?? "not yet run"}</span></p>
      <a class="button-link" href="#/canvas?wf=${encodeURIComponent(pack.workflow_id)}">Open in Canvas</a>
    </article>`;
}

export async function renderChoose(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Loading workflow packs…</p>`;
  const result = await fetchWithFallback("/workflows", { port, token });

  if (result.state === "unavailable") {
    root.innerHTML = `<p class="unavailable-state">Workflow packs aren't available in this daemon yet — the run engine ships in a later Helm wave. This page will populate automatically once it does.</p>`;
    return;
  }
  if (result.state === "missing") {
    root.innerHTML = `<p class="empty-state">Can't reach helmd on port ${port}. Start the daemon and open its pairing link to choose a workflow.</p>`;
    return;
  }

  const packs = result.data?.workflows ?? [];
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";

  if (packs.length === 0) {
    root.innerHTML = `<p class="empty-state">No workflow packs configured yet.${staleBadge}</p>`;
    return;
  }

  root.innerHTML = `
    <h2>Choose${staleBadge}</h2>
    <p class="field-row">Outcome-oriented workflow packs — not a raw inventory. Pick one to review its manifest.</p>
    <div class="card-grid">${packs.map(packCard).join("")}</div>`;
}
