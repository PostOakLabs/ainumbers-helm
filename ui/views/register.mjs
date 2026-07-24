// Register view (HELM-P3-E12): one-click EUC register entry + per-kernel
// validation card exports. Turns SR 11-7/SS1-23 model-risk paperwork into a
// button instead of a hand-maintained spreadsheet — generated entirely from
// the compiled pack + vendored kernel metadata already on the daemon
// (hub/euc-register.mjs); nothing here is persisted.
import { fetchWithFallback, call, callText } from "../api.mjs";

function downloadBlob(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

const FORMAT_EXT = { html: "html", table: "html", dmn: "dmn", json: "json" };
const FORMAT_MIME = { html: "text/html", table: "text/html", dmn: "application/xml", json: "application/json" };

async function triggerDownload(root, { port, token, path, filenameBase, format, setStatus }) {
  setStatus("Generating…");
  const res = await callText(`${path}${path.includes("?") ? "&" : "?"}format=${format}`, { port, token });
  if (!res.ok) {
    setStatus(`Failed: ${typeof res.error === "string" ? res.error : res.status}`);
    return;
  }
  const ext = FORMAT_EXT[format] ?? "json";
  const mime = FORMAT_MIME[format] ?? "application/json";
  downloadBlob(`${filenameBase}.${ext}`, res.text, mime);
  setStatus("Downloaded.");
}

function kernelRow(kernelId) {
  return `
    <li class="field-row" data-kernel-id="${kernelId}">
      <span><code>${kernelId}</code></span>
      <span>
        <button type="button" class="secondary" data-action="card" data-format="json">JSON</button>
        <button type="button" class="secondary" data-action="card" data-format="html">HTML</button>
        <button type="button" class="secondary" data-action="card" data-format="table">Decision table</button>
        <button type="button" class="secondary" data-action="card" data-format="dmn">DMN XML</button>
      </span>
      <span class="field-row-note" data-role="status"></span>
    </li>`;
}

export async function renderRegister(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Loading workflow packs…</p>`;
  const result = await fetchWithFallback("/workflows", { port, token });

  if (result.state === "unavailable") {
    root.innerHTML = `<p class="unavailable-state">Workflow packs aren't available in this daemon yet.</p>`;
    return;
  }
  if (result.state === "missing") {
    root.innerHTML = `<p class="empty-state">Can't reach helmd on port ${port}.</p>`;
    return;
  }

  const packs = result.data?.workflows ?? [];
  if (packs.length === 0) {
    root.innerHTML = `<p class="empty-state">No workflow packs configured yet.</p>`;
    return;
  }

  root.innerHTML = `
    <h2>Register</h2>
    <p class="field-row">EUC register entries and per-kernel validation cards — SR 11-7/SS1-23 model-risk paperwork, generated instead of hand-maintained.</p>
    <form id="register-form">
      <label for="wf-select">Workflow</label>
      <select id="wf-select">${packs.map((p) => `<option value="${p.workflow_id}">${p.name ?? p.workflow_id}</option>`).join("")}</select>
      <label for="owner-input">Owner</label>
      <input id="owner-input" type="text" placeholder="e.g. Benefits Compliance Officer" />
      <label for="purpose-input">Purpose (defaults to the pack's outcome if left blank)</label>
      <input id="purpose-input" type="text" />
      <label for="control-input">Control description</label>
      <input id="control-input" type="text" placeholder="e.g. reviewed quarterly against published thresholds" />
      <label for="validated-input">Last validated</label>
      <input id="validated-input" type="date" />
    </form>
    <p>
      <button type="button" id="entry-json" class="secondary">Download EUC entry (JSON)</button>
      <button type="button" id="entry-html" class="secondary">Download EUC entry (HTML)</button>
      <span id="entry-status" class="field-row-note" role="status"></span>
    </p>
    <h3>Kernel validation cards</h3>
    <ul id="kernel-list" class="field-list"><li class="empty-state">Select a workflow to list its kernels.</li></ul>`;

  const wfSelect = root.querySelector("#wf-select");
  const kernelList = root.querySelector("#kernel-list");
  const entryStatus = root.querySelector("#entry-status");

  function eucEntryQuery() {
    const owner = root.querySelector("#owner-input").value.trim();
    const purpose = root.querySelector("#purpose-input").value.trim();
    const control = root.querySelector("#control-input").value.trim();
    const validated = root.querySelector("#validated-input").value.trim();
    const params = new URLSearchParams();
    if (owner) params.set("owner", owner);
    if (purpose) params.set("purpose", purpose);
    if (control) params.set("control_description", control);
    if (validated) params.set("last_validated", validated);
    return params.toString();
  }

  async function loadKernels(workflowId) {
    kernelList.innerHTML = `<li aria-live="polite">Loading kernels…</li>`;
    const manifestRes = await call(`/workflow-manifest?workflow_id=${encodeURIComponent(workflowId)}`, { port, token });
    if (!manifestRes.ok) {
      kernelList.innerHTML = `<li class="empty-state">Couldn't load this workflow's kernels.</li>`;
      return;
    }
    const nodes = manifestRes.data?.nodes ?? [];
    if (nodes.length === 0) {
      kernelList.innerHTML = `<li class="empty-state">This workflow has no kernel nodes.</li>`;
      return;
    }
    const seen = new Set();
    const uniqueKernelIds = nodes.map((n) => n.kernel_id).filter((id) => (seen.has(id) ? false : seen.add(id)));
    kernelList.innerHTML = uniqueKernelIds.map(kernelRow).join("");
  }

  wfSelect.addEventListener("change", () => loadKernels(wfSelect.value));
  await loadKernels(wfSelect.value);

  kernelList.addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-action='card']");
    if (!btn) return;
    const li = btn.closest("li[data-kernel-id]");
    const kernelId = li.dataset.kernelId;
    const statusEl = li.querySelector("[data-role='status']");
    triggerDownload(root, {
      port,
      token,
      path: `/kernels/${encodeURIComponent(kernelId)}/card`,
      filenameBase: `kernel-card-${kernelId}`,
      format: btn.dataset.format,
      setStatus: (t) => (statusEl.textContent = t),
    });
  });

  root.querySelector("#entry-json").addEventListener("click", () =>
    triggerDownload(root, {
      port,
      token,
      path: `/workflows/${encodeURIComponent(wfSelect.value)}/euc-entry?${eucEntryQuery()}`,
      filenameBase: `euc-entry-${wfSelect.value}`,
      format: "json",
      setStatus: (t) => (entryStatus.textContent = t),
    })
  );
  root.querySelector("#entry-html").addEventListener("click", () =>
    triggerDownload(root, {
      port,
      token,
      path: `/workflows/${encodeURIComponent(wfSelect.value)}/euc-entry?${eucEntryQuery()}`,
      filenameBase: `euc-entry-${wfSelect.value}`,
      format: "html",
      setStatus: (t) => (entryStatus.textContent = t),
    })
  );
}
