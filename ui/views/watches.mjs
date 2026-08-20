// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Watches view (HELM-WATCH-UI-1, HELM-WATCH-BUILD-SPEC.md §1 Q6, §4 row 4).
// List/create/detail over the watch-scheduler API (GET/POST /watches, GET
// /watches/{id}, POST /watches/{id}/revoke) and the freshness-receipt read
// this row added at GET /watches/{id}/receipt (HELM-WATCH-RECEIPT-1 shipped
// the computation, hub/receipt.mjs's computeFreshnessReceipt, but wired no
// HTTP route for it — that gap sat outside every row's stated fence, so this
// row closed it with one mechanical read-only route rather than stopping;
// see this row's check-off for the note).
//
// KNOWN SCOPE NARROWING vs. spec Q6's literal words: Q6 asks for "receipt
// history for one watch". The underlying data model (watch-scheduler.mjs's
// watch_runs table) keeps only the LATEST firing per watch, not a log of
// every past one — computeFreshnessReceipt is a single computed-at-read-time
// view (Q2: "never a parallel source of truth"), not a stored series. There
// is therefore no plural history to show yet; Detail below renders the one
// current receipt honestly, never a fabricated list. Recorded as a finding,
// not silently guessed around.
//
// Consent (Q5): a watch is standing config, so creation is consent-gated —
// this view signs a consent record with the SAME browser-held-key path
// review.mjs's HA countersignature UI uses (ha-crypto.mjs), never a
// daemon-held key. consent_ref is the sha256 digest of that signed record;
// helmd stores it opaquely (watch-scheduler.mjs's validateWatchInput never
// re-verifies the signature — it only refuses a missing consent_ref).
import { fetchWithFallback, call } from "../api.mjs";
import { loadOrCreateBrowserIdentity } from "../lib/ha-crypto.mjs";
import { sign } from "../vendored/proof.mjs";
import { manifestDigest, cgCanon } from "../lib/manifest-digest.mjs";
import { esc } from "../lib/esc.mjs";
import { blockedStateHtml, classifyBlockedState } from "../lib/blocked-state.mjs";

const ALERT_KINDS = ["miss", "result_change", "gate_hold"];

async function sha256HexOfObject(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(cgCanon(obj)));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function watchStatusBadge(status) {
  const label = status ?? "unknown";
  return `<span class="watch-status-badge" data-status="${esc(label)}">${esc(label)}</span>`;
}

function cadenceText(cadence) {
  return `every ${cadence.interval} ${cadence.unit}`;
}

// Q6: "next-expected-by (computed, labeled as an estimate, never 'scheduled
// for')" — the wording is load-bearing (SO #0: no promise about a future
// moment), not a copy nicety.
function nextExpectedLine(receipt) {
  const by = receipt?.cadence_conformance?.expected_by;
  if (!by) return "";
  return `<p class="field-row-note">Next expected by (estimate): <strong>${esc(by)}</strong></p>`;
}

function receiptSummaryLine(receipt) {
  if (!receipt) return `<p class="field-row-note">No receipt computed yet.</p>`;
  return `${watchStatusBadge(receipt.status)} ${nextExpectedLine(receipt)}`;
}

function watchListRow(watch, receipt) {
  return `
    <li class="card watch-card" aria-labelledby="watch-${esc(watch.watch_id)}">
      <h3 id="watch-${esc(watch.watch_id)}"><a href="#/watches?id=${encodeURIComponent(watch.watch_id)}">${esc(watch.watch_id)}</a></h3>
      <dl>
        <div class="field-row"><dt>Pack</dt><dd><code>${esc(watch.pack_ref.pack_id)}</code></dd></div>
        <div class="field-row"><dt>Cadence</dt><dd>${esc(cadenceText(watch.cadence))}</dd></div>
      </dl>
      ${receiptSummaryLine(receipt)}
    </li>`;
}

async function renderList(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Checking helmd for watches…</p>`;
  const result = await fetchWithFallback("/watches", { port, token });

  const blocked = classifyBlockedState(result);
  if (blocked) {
    root.innerHTML = blockedStateHtml(blocked, {
      port,
      status: result.status,
      route: result.route,
      body: blocked === "too-old" ? "helmd answered, but watches aren't part of this version of Helm yet." : "Helm is running, but this tab can't reach the watch scheduler right now.",
    });
    return;
  }

  const watches = result.data?.watches ?? [];
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";

  if (!watches.length) {
    root.innerHTML = `
      ${staleBadge ? `<p class="view-subtitle">${staleBadge}</p>` : ""}
      <p class="empty-state">No watches yet. A watch fires a pack unattended on a fixed schedule and leaves a signed freshness receipt behind each time — create one below to turn a pack you already run by hand into a standing check.</p>
      <a class="button-link" href="#/watches?new=1">Create a watch</a>`;
    return;
  }

  const receipts = await Promise.all(
    watches.map(async (w) => {
      const res = await call(`/watches/${encodeURIComponent(w.watch_id)}/receipt`, { port, token });
      return res.ok ? res.data.receipt : null;
    })
  );

  root.innerHTML = `
    ${staleBadge ? `<p class="view-subtitle">${staleBadge}</p>` : ""}
    <p class="field-row">Watches (${watches.length}) — packs Helm runs on its own, on a fixed schedule.</p>
    <a class="button-link" href="#/watches?new=1">Create a watch</a>
    <ul class="card-grid">${watches.map((w, i) => watchListRow(w, receipts[i])).join("")}</ul>`;
}

async function packOptionsHtml(port, token) {
  const result = await fetchWithFallback("/workflows", { port, token });
  const packs = result.data?.workflows ?? [];
  if (!packs.length) return { html: "", packs: [] };
  const html = packs.map((p) => `<option value="${esc(p.workflow_id)}">${esc(p.name ?? p.workflow_id)}</option>`).join("");
  return { html, packs };
}

function createFormHtml(packOptionsHtmlStr) {
  return `
    <section class="card" aria-labelledby="watch-create-heading">
      <h3 id="watch-create-heading">Create a watch</h3>
      <form id="watch-create-form">
        <label>Pack
          <select name="pack_id" required>${packOptionsHtmlStr}</select>
        </label>
        <div class="button-row" role="group" aria-label="Cadence">
          <label>Every
            <input type="number" name="interval" min="1" step="1" value="1" required>
          </label>
          <label>Unit
            <select name="unit">
              <option value="hours">hours</option>
              <option value="days" selected>days</option>
              <option value="weeks">weeks</option>
            </select>
          </label>
        </div>
        <label>Inputs
          <select name="inputs_mode">
            <option value="sample" selected>Use the pack's own sample/fixture data</option>
            <option value="operator_supplied">Supply fixed inputs now (re-used on every firing)</option>
          </select>
        </label>
        <label id="watch-operator-inputs-label" class="field-hidden">Inputs (JSON, keyed by node_id)
          <textarea name="operator_inputs" rows="4" placeholder='{"node_a": {"param": "value"}}'></textarea>
        </label>
        <fieldset>
          <legend>Alert on</legend>
          ${ALERT_KINDS.map((k) => `<label><input type="checkbox" name="alert_on" value="${k}"> ${esc(k)}</label>`).join(" ")}
        </fieldset>
        <p class="field-row-note">Creating a watch signs a consent record with your browser-held key, the same way an approval is signed on Review — this is the standing authorization for helmd to run this pack unattended, per this watch's cadence, starting now.</p>
        <div class="button-row">
          <button type="submit">Sign consent and create watch</button>
        </div>
        <p class="watch-create-result" role="status" aria-live="polite"></p>
      </form>
    </section>`;
}

async function submitCreate(root, port, token, form, resultEl, rerender) {
  const fd = new FormData(form);
  const packId = fd.get("pack_id");
  if (!packId) {
    resultEl.textContent = "No pack selected — create one on Choose first.";
    return;
  }
  resultEl.textContent = "Reading pack manifest…";
  const manifestRes = await call(`/workflow-manifest?workflow_id=${encodeURIComponent(packId)}`, { port, token });
  if (!manifestRes.ok) {
    resultEl.textContent = `Could not read pack "${packId}": ${JSON.stringify(manifestRes.error)}`;
    return;
  }
  const packDigest = await manifestDigest(manifestRes.data);

  const inputsMode = fd.get("inputs_mode");
  let inputsSource = { mode: "sample" };
  if (inputsMode === "operator_supplied") {
    try {
      inputsSource = { mode: "operator_supplied", inputs: JSON.parse(fd.get("operator_inputs") || "{}") };
    } catch {
      resultEl.textContent = "Inputs JSON doesn't parse — fix it and try again.";
      return;
    }
  }

  const alertOn = fd.getAll("alert_on");
  const cadence = { unit: fd.get("unit"), interval: Number(fd.get("interval")) };

  resultEl.textContent = "Signing consent in browser…";
  const identity = await loadOrCreateBrowserIdentity();
  const nowISO = new Date().toISOString();
  const unsignedConsent = {
    record_type: "watch_consent",
    pack_id: packId,
    pack_digest: packDigest,
    cadence,
    identity: { id: identity.id },
    timestamp: nowISO,
  };
  const signedConsent = await sign(unsignedConsent, { verificationMethod: `${identity.id}#key-1`, created: nowISO, privateKey: identity.privateKey });
  const consentRef = `sha256:${await sha256HexOfObject(signedConsent)}`;

  const body = {
    pack_ref: { pack_id: packId, pack_digest: packDigest },
    cadence,
    inputs_source: inputsSource,
    ...(alertOn.length ? { alert_on: alertOn } : {}),
    created_by: { id: identity.id },
    consent_ref: consentRef,
  };

  resultEl.textContent = "Creating watch…";
  const res = await call("/watches", { port, token, method: "POST", body });
  if (!res.ok) {
    resultEl.textContent = `Refused: ${JSON.stringify(res.error ?? res.data)}`;
    return;
  }
  resultEl.textContent = `Watch created: ${res.data.watch.watch_id}`;
  location.hash = `#/watches?id=${encodeURIComponent(res.data.watch.watch_id)}`;
  await rerender();
}

async function renderCreate(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Loading packs…</p>`;
  const { html: optionsHtml, packs } = await packOptionsHtml(port, token);
  if (!packs.length) {
    root.innerHTML = `<p class="empty-state">No packs to watch yet. <a href="#/choose">Choose</a> or build one first — a watch always fires an existing pack, it never invents one.</p>`;
    return;
  }
  root.innerHTML = createFormHtml(optionsHtml);

  const form = root.querySelector("#watch-create-form");
  const inputsModeSelect = form.querySelector('[name="inputs_mode"]');
  const operatorInputsLabel = root.querySelector("#watch-operator-inputs-label");
  inputsModeSelect.addEventListener("change", () => {
    operatorInputsLabel.classList.toggle("field-hidden", inputsModeSelect.value !== "operator_supplied");
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const resultEl = form.querySelector(".watch-create-result");
    await submitCreate(root, port, token, form, resultEl, () => renderWatches(root, { port, token, params: new URLSearchParams() }));
  });
}

function receiptDetailHtml(receipt) {
  if (!receipt) return `<p class="empty-state">No receipt computed yet for this watch.</p>`;
  const cc = receipt.cadence_conformance ?? {};
  return `
    <dl>
      <div class="field-row"><dt>Status</dt><dd>${watchStatusBadge(receipt.status)}</dd></div>
      <div class="field-row"><dt>As of</dt><dd>${esc(receipt.as_of)}</dd></div>
      <div class="field-row"><dt>Expected by</dt><dd>${esc(cc.expected_by)}</dd></div>
      <div class="field-row"><dt>Ran at</dt><dd>${esc(cc.ran_at ?? "—")}</dd></div>
      <div class="field-row"><dt>Within window</dt><dd>${cc.within_window ? "yes" : "no"}</dd></div>
      <div class="field-row"><dt>Journal entry</dt><dd>${receipt.entry_digest ? `<code title="${esc(receipt.entry_digest)}">${esc(receipt.entry_digest.slice(0, 20))}…</code>` : "—"}</dd></div>
      ${receipt.evidences?.length ? `<div class="field-row"><dt>Evidences</dt><dd>${receipt.evidences.map((e) => `${esc(e.framework)} ${esc(e.control_id)}`).join(", ")}</dd></div>` : ""}
    </dl>
    <p class="field-row-note">A dated observation, not a promise (Helm's own §0 rule) — this states what was true as of the timestamp above, never a commitment about what happens next.</p>`;
}

async function revokeWatchAction(port, token, watchId, identity, resultEl, rerender) {
  resultEl.textContent = "Revoking…";
  const res = await call(`/watches/${encodeURIComponent(watchId)}/revoke`, { port, token, method: "POST", body: { revoked_by: identity.id } });
  resultEl.textContent = res.ok ? "Watch revoked. Its history stays intact — only future firings stop." : `Refused: ${JSON.stringify(res.error)}`;
  await rerender();
}

async function renderDetail(root, { port, token }, watchId) {
  root.innerHTML = `<p aria-live="polite">Loading watch…</p>`;
  const [watchRes, receiptRes] = await Promise.all([
    call(`/watches/${encodeURIComponent(watchId)}`, { port, token }),
    call(`/watches/${encodeURIComponent(watchId)}/receipt`, { port, token }),
  ]);

  if (!watchRes.ok) {
    root.innerHTML = watchRes.status === 404
      ? `<p class="empty-state">No watch with id "${esc(watchId)}" — it may have been revoked. <a href="#/watches">Back to watches</a>.</p>`
      : blockedStateHtml("not-paired", { port, status: watchRes.status, body: "Helm is running, but this tab can't reach that watch right now." });
    return;
  }

  const watch = watchRes.data.watch;
  const receipt = receiptRes.ok ? receiptRes.data.receipt : null;
  const identity = await loadOrCreateBrowserIdentity();

  root.innerHTML = `
    <p><a href="#/watches">&larr; All watches</a></p>
    <section class="card" aria-labelledby="watch-detail-heading">
      <h3 id="watch-detail-heading"><code>${esc(watch.watch_id)}</code></h3>
      <dl>
        <div class="field-row"><dt>Pack</dt><dd><code>${esc(watch.pack_ref.pack_id)}</code></dd></div>
        <div class="field-row"><dt>Cadence</dt><dd>${esc(cadenceText(watch.cadence))}</dd></div>
        <div class="field-row"><dt>Inputs</dt><dd>${esc(watch.inputs_source.mode)}</dd></div>
        <div class="field-row"><dt>Alert on</dt><dd>${watch.alert_on?.length ? esc(watch.alert_on.join(", ")) : "nothing (opted out)"}</dd></div>
        <div class="field-row"><dt>Created</dt><dd>${esc(watch.created_at)} by <code>${esc(watch.created_by.id)}</code></dd></div>
        <div class="field-row"><dt>Consent</dt><dd><code title="${esc(watch.consent_ref)}">${esc(watch.consent_ref.slice(0, 24))}…</code></dd></div>
      </dl>
      <div class="button-row">
        <button type="button" class="secondary watch-revoke-btn">Revoke watch</button>
      </div>
      <p class="watch-detail-result" role="status" aria-live="polite"></p>
    </section>
    <section class="card" aria-labelledby="watch-receipt-heading">
      <h3 id="watch-receipt-heading">Freshness receipt</h3>
      <p class="field-row-note">This shows the one current receipt, computed fresh each time this page is opened — Helm doesn't keep a log of every past firing yet, only the latest.</p>
      ${receiptDetailHtml(receipt)}
    </section>`;

  root.querySelector(".watch-revoke-btn")?.addEventListener("click", () => {
    const resultEl = root.querySelector(".watch-detail-result");
    revokeWatchAction(port, token, watch.watch_id, identity, resultEl, () => renderDetail(root, { port, token }, watchId));
  });
}

export async function renderWatches(root, { port, token, params } = {}) {
  if (!port || !token) {
    root.innerHTML = `<p class="empty-state">helmd isn't paired yet. Pair a browser tab (see Status) to see or create watches on this computer.</p>`;
    return;
  }

  const qs = params ?? new URLSearchParams(location.hash.split("?")[1] || "");
  const watchId = qs.get("id");
  if (watchId) return renderDetail(root, { port, token }, watchId);
  if (qs.get("new") === "1") return renderCreate(root, { port, token });
  return renderList(root, { port, token });
}
