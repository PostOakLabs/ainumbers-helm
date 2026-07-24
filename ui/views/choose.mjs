// Choose view: an outcome-oriented list of workflow packs, NOT a raw
// inventory of every manifest on disk. Selecting one opens Canvas
// (read-only DAG first; authoring is a stretch goal per HELM-U2).
import { fetchWithFallback } from "../api.mjs";

function templateCard(t) {
  return `
    <article class="card" aria-labelledby="template-${t.slug}">
      <h3 id="template-${t.slug}">${t.title}</h3>
      <p class="field-row-note">${t.blurb}</p>
      <a class="button-link" href="#template=${encodeURIComponent(t.slug)}">Run template</a>
    </article>`;
}

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
  const [result, templatesResult] = await Promise.all([
    fetchWithFallback("/workflows", { port, token }),
    fetchWithFallback("/templates", { port, token }),
  ]);

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

  const templates = templatesResult.state === "live" || templatesResult.state === "stale" ? (templatesResult.data?.templates ?? []) : [];
  const templatesRail = templates.length
    ? `<section aria-label="Templates">
        <h3>Templates</h3>
        <p class="field-row">Compliance-scenario templates pre-wired with sample data — pick one to run end to end.</p>
        <div class="card-grid">${templates.map(templateCard).join("")}</div>
      </section>`
    : "";

  root.innerHTML = `
    <h2>Choose${staleBadge}</h2>
    ${templatesRail}
    <p class="field-row">Outcome-oriented workflow packs — not a raw inventory. Pick one to review its manifest.</p>
    <div class="card-grid">${packs.map(packCard).join("")}</div>`;
}
