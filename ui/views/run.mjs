// Run view: timeline of execution_state transitions (schema/objects/
// execution_state.schema.json — §26.4/§26.5 lifecycle), dry-run trigger,
// data-classification markers (from connector_attestation.classification
// entries attached to a run), live SSE progress, pause/cancel. The run
// engine (HELM-H4/H6/H7) hasn't shipped yet, so every call below degrades
// to the same dormant-state discipline as Connect/Operate — it lights up
// with no UI changes once those routes exist.
import { fetchWithFallback, call } from "../api.mjs";

// EventSource can't set an Authorization header, and D8 loopback bind means
// this token only ever reaches 127.0.0.1 — carrying it in the query string
// here is a deliberate, narrow exception to the "bearer header only" rule,
// scoped to this one SSE connection. Flagged for HELM-R1 security review.
function openProgressStream(port, token, runId, onEvent) {
  const url = `http://127.0.0.1:${port}/events?run_id=${encodeURIComponent(runId)}&token=${encodeURIComponent(token)}`;
  let es;
  try {
    es = new EventSource(url);
  } catch {
    return () => {};
  }
  es.addEventListener("progress", (ev) => onEvent(JSON.parse(ev.data)));
  es.onerror = () => onEvent(null, true);
  return () => es.close();
}

const STATE_LABELS = {
  draft: "Draft", validated: "Validated", queued: "Queued", running: "Running",
  awaiting_data: "Awaiting data", awaiting_review: "Awaiting review", approved: "Approved",
  rejected: "Rejected", overridden: "Overridden", executing_action: "Executing action",
  submitted: "Submitted", acknowledged: "Acknowledged", completed: "Completed",
  failed: "Failed", cancelled: "Cancelled",
};

function timelineEntry(step) {
  const classBadge = step.classification
    ? `<span class="classification-badge" data-level="${step.classification}">${step.classification}</span>`
    : "";
  return `
    <li class="timeline-entry" data-state="${step.state}">
      <span class="timeline-state">${STATE_LABELS[step.state] ?? step.state}</span>
      <span class="timeline-time">${step.recorded_at ?? ""}</span>
      ${classBadge}
    </li>`;
}

async function triggerRun(port, token, workflowId, dryRun, resultEl, templateSlug) {
  resultEl.textContent = dryRun ? "Starting dry-run…" : "Starting run…";
  const body = templateSlug ? { template_slug: templateSlug, dry_run: dryRun } : { workflow_id: workflowId, dry_run: dryRun };
  const res = await call("/run/start", { port, token, method: "POST", body });
  if (res.ok) {
    const runId = res.data?.run_id;
    resultEl.textContent = `${dryRun ? "Dry-run" : "Run"} started: ${runId ?? "pending"}.`;
    // Re-render this view with ?run=<id> so the timeline + SSE stream below
    // pick it up — a hashchange, not a fresh navigation, so it lands on the
    // same view with the run now attached. Drops the template param: the
    // workflow_id it resolved to is now known, and the manifest is memoized
    // to this run_id regardless.
    if (runId) location.hash = `#/run?wf=${encodeURIComponent(workflowId)}&run=${encodeURIComponent(runId)}`;
  } else if (res.status === 404) {
    resultEl.textContent = "The run engine isn't available in this daemon version yet.";
  } else {
    resultEl.textContent = "helmd unreachable — nothing was started.";
  }
}

async function runControl(port, token, action, runId, resultEl) {
  resultEl.textContent = `Requesting ${action}…`;
  const res = await call(`/run/${action}`, { port, token, method: "POST", body: { run_id: runId } });
  resultEl.textContent = res.ok ? `${action} acknowledged.` : `${action} not available yet.`;
}

export async function renderRun(root, { port, token, params }) {
  let workflowId = params?.get("wf") ?? "";
  const runId = params?.get("run") ?? "";
  const templateSlug = !workflowId ? (params?.get("template") ?? "") : "";

  root.innerHTML = `<p aria-live="polite">Loading run state…</p>`;

  let templateBanner = "";
  if (templateSlug) {
    const tpl = await fetchWithFallback(`/templates/${encodeURIComponent(templateSlug)}`, { port, token });
    if (tpl.state === "unavailable" || tpl.state === "missing") {
      root.innerHTML = `<p class="empty-state">Can't load the "${templateSlug}" template — pair with helmd on this computer, then open this link again.</p>`;
      return;
    }
    workflowId = tpl.data?.workflow_id ?? "";
    templateBanner = `
      <div class="card">
        <h3>${tpl.data?.title ?? templateSlug}</h3>
        <p class="field-row-note">${tpl.data?.blurb ?? ""}</p>
        <p class="field-row"><span>Sample data</span><span>pre-wired — nothing to fill in</span></p>
      </div>`;
  }

  const timeline = await fetchWithFallback(`/run/timeline${runId ? `?run_id=${encodeURIComponent(runId)}` : ""}`, { port, token });

  const staleBadge = timeline.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${timeline.at}</span>` : "";
  const steps = timeline.data?.steps ?? [];
  const timelineHtml =
    timeline.state === "unavailable"
      ? `<p class="unavailable-state">The run engine isn't available in this daemon yet — it ships in a later Helm wave.</p>`
      : steps.length === 0
        ? `<p class="empty-state">No run history yet.</p>`
        : `<ol class="timeline">${steps.map(timelineEntry).join("")}</ol>`;

  const startCard = templateSlug
    ? `<div class="card">
        <h3>Start</h3>
        <p class="field-row">One click runs this template end to end with its sample data.</p>
        <button type="button" id="live-run-btn">Run template</button>
        <button type="button" id="dry-run-btn" class="secondary">Dry-run instead</button>
        <p id="start-result" role="status" aria-live="polite"></p>
      </div>`
    : `<div class="card">
        <h3>Start</h3>
        <p class="field-row">Dry-run replays the manifest without side effects; a live run may call connectors and actions.</p>
        <button type="button" id="dry-run-btn">Dry-run</button>
        <button type="button" id="live-run-btn" class="secondary">Run live</button>
        <p id="start-result" role="status" aria-live="polite"></p>
      </div>`;

  root.innerHTML = `
    <h2>Run${workflowId ? ` — ${workflowId}` : ""}${staleBadge}</h2>
    ${templateBanner}
    ${startCard}
    <div class="card">
      <h3>Timeline${runId ? ` — ${runId}` : ""}</h3>
      <p id="live-indicator" class="empty-state" role="status" aria-live="polite">not streaming</p>
      ${timelineHtml}
    </div>
    <div class="card">
      <h3>Controls</h3>
      <button type="button" id="pause-btn" class="secondary">Pause</button>
      <button type="button" id="cancel-btn" class="secondary">Cancel</button>
      <p id="control-result" role="status" aria-live="polite"></p>
    </div>`;

  const startResult = root.querySelector("#start-result");
  root.querySelector("#dry-run-btn").addEventListener("click", () => triggerRun(port, token, workflowId, true, startResult, templateSlug));
  root.querySelector("#live-run-btn").addEventListener("click", () => triggerRun(port, token, workflowId, false, startResult, templateSlug));

  const controlResult = root.querySelector("#control-result");
  root.querySelector("#pause-btn").addEventListener("click", () => runControl(port, token, "pause", runId, controlResult));
  root.querySelector("#cancel-btn").addEventListener("click", () => runControl(port, token, "cancel", runId, controlResult));

  if (runId && typeof EventSource !== "undefined") {
    const indicator = root.querySelector("#live-indicator");
    const close = openProgressStream(port, token, runId, (data, errored) => {
      if (errored) {
        indicator.textContent = "stream disconnected — retry from Run";
        return;
      }
      indicator.textContent = `live — last event: ${STATE_LABELS[data?.state] ?? data?.state ?? "update"}`;
    });
    // The shell re-renders #shell-main in place on navigation rather than
    // replacing the element, so leaving this view is a hashchange, not a
    // DOM removal — close the stream on the next navigation, once.
    window.addEventListener("hashchange", close, { once: true });
  }
}
