// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Review view (HELM-HA-1 §1 item 4): the §27 approve/reject queue. Lists
// every run helmd is holding at a §27.4 gate (GET /ha/pending), shows the
// evidence collected so far for each, and lets the browser's own local
// approver identity (ha-crypto.mjs) sign an approval/rejection in place —
// helmd verifies the signature server-side (POST /ha/records) and never
// sees the private key. A separate "Replay-verify" action asks helmd to
// re-execute the PRECEDING step's kernel itself and countersign with a real
// replay_verified — the Helm-only maker-checker differentiator.
import { fetchWithFallback, call } from "../api.mjs";
import { loadOrCreateBrowserIdentity, signHaRecord, signBundleDigest } from "../lib/ha-crypto.mjs";
import { esc } from "../lib/esc.mjs";
import { blockedStateHtml, classifyBlockedState } from "../lib/blocked-state.mjs";

function shortHash(h) {
  return h && h.length > 20 ? `${h.slice(0, 14)}…${h.slice(-6)}` : h;
}

function recordRow(r) {
  return `<li><code>${esc(r.record_type)}</code> · ${esc(r.role)} · ${esc(r.identity?.id)} ${r.decision ? `→ ${esc(r.decision)}` : ""}</li>`;
}

// HELM-MAKERCHECKER-BUILD-SPEC.md §4: what the countersignature_slot for
// this item's own subject looks like right now — maker_signature present or
// null (MC-1.1), and each countersignature's attester_kind (E-4). Distinct
// from the §27.2 approve/reject records above: two independent evidence
// trails over the same subject, per the spec's §2 "both layers load-bearing"
// verdict.
function slotSummary(slot) {
  if (!slot) return `<p class="empty-state">No countersignature slot yet for this subject.</p>`;
  const maker = slot.maker_signature
    ? `<code title="${esc(slot.maker_signature.keyid)}">${esc(shortHash(slot.maker_signature.keyid))}</code>`
    : `<em>none yet</em>`;
  const checkers = (slot.countersignatures ?? [])
    .map((c) => `<li><code>${esc(shortHash(c.identity?.id))}</code> · ${esc(c.attester_kind ?? "unknown")}${"replay_verified" in c ? ` · replay ${c.replay_verified ? "matched" : "did not match"}` : ""}</li>`)
    .join("");
  return `
    <div class="field-row"><dt>Maker</dt><dd>${maker}</dd></div>
    ${checkers ? `<ul>${checkers}</ul>` : `<p class="empty-state">No countersignatures yet.</p>`}`;
}

function pendingCard(item, myIdentityId, slot) {
  const already = (item.records ?? []).some((r) => r.identity?.id === myIdentityId);
  const hasMaker = !!slot?.maker_signature;
  const alreadyCountersigned = (slot?.countersignatures ?? []).some((c) => c.identity?.id === myIdentityId);
  const exportBlob = hasMaker ? JSON.stringify({ subject_hash: item.subjectHash, maker_signature: slot.maker_signature }, null, 2) : "";
  return `
    <section class="card" aria-labelledby="ha-${esc(item.run_id)}">
      <h3 id="ha-${esc(item.run_id)}">${esc(item.step_id)} <span class="phase-stub-badge">${esc(item.gatePolicy)}</span></h3>
      <dl>
        <div class="field-row"><dt>Run</dt><dd><code>${esc(item.run_id)}</code></dd></div>
        <div class="field-row"><dt>Role required</dt><dd>${esc(item.role)}</dd></div>
        <div class="field-row"><dt>Threshold</dt><dd>${item.threshold ?? 1}</dd></div>
        <div class="field-row"><dt>Subject hash</dt><dd><code title="${esc(item.subjectHash)}">${esc(shortHash(item.subjectHash))}</code></dd></div>
      </dl>
      <p class="empty-state">${esc(item.reason)}</p>
      ${item.records?.length ? `<ul>${item.records.map(recordRow).join("")}</ul>` : `<p class="empty-state">No accountability records yet.</p>`}
      <div class="button-row">
        <button type="button" class="approve-btn" data-run="${esc(item.run_id)}" data-subject="${esc(item.subjectHash)}" data-role="${esc(item.role)}" ${already ? "disabled" : ""}>Approve</button>
        <button type="button" class="reject-btn" data-run="${esc(item.run_id)}" data-subject="${esc(item.subjectHash)}" data-role="${esc(item.role)}" ${already ? "disabled" : ""}>Reject</button>
        <button type="button" class="replay-btn" data-run="${esc(item.run_id)}">Replay-verify</button>
        <button type="button" class="resume-btn" data-run="${esc(item.run_id)}">Resume run</button>
      </div>
      <p class="ha-result" id="ha-result-${esc(item.run_id)}" role="status" aria-live="polite"></p>

      <details class="makerchecker-detail">
        <summary>Maker-checker (separate from the approve/reject above)</summary>
        <dl>${slotSummary(slot)}</dl>
        <div class="button-row">
          <button type="button" class="maker-sign-btn" data-subject="${esc(item.subjectHash)}" ${hasMaker ? "disabled" : ""}>Sign as maker</button>
          <button type="button" class="countersign-btn" data-subject="${esc(item.subjectHash)}" ${!hasMaker || alreadyCountersigned ? "disabled" : ""}>Countersign as checker</button>
        </div>
        ${hasMaker ? `
        <label>Export — copy this to a checker with no access to this helmd:
          <textarea class="export-blob" readonly rows="4">${esc(exportBlob)}</textarea>
        </label>` : ""}
        <label>Import a countersignature received out of band:
          <textarea class="import-blob" rows="4" placeholder='{"subject_hash":"sha256:...","countersignature":{...}}'></textarea>
        </label>
        <div class="button-row">
          <button type="button" class="import-countersign-btn" data-subject="${esc(item.subjectHash)}">Submit imported countersignature</button>
        </div>
        <p class="ha-result" id="mc-result-${esc(item.run_id)}" role="status" aria-live="polite"></p>
      </details>
    </section>`;
}

async function submitDecision(port, token, { runId, subjectHash, role, decision }, resultEl) {
  resultEl.textContent = "Signing in browser…";
  try {
    const identity = await loadOrCreateBrowserIdentity();
    const nowISO = new Date().toISOString();
    const record = await signHaRecord(
      { recordType: "approval", role, subjectHash, identityId: identity.id, decision, reasonCode: decision === "approve" ? "REVIEWED_OK" : "REVIEWED_REJECT", nowISO },
      identity
    );
    const res = await call("/ha/records", { port, token, method: "POST", body: { record } });
    resultEl.textContent = res.ok ? `${decision === "approve" ? "Approved" : "Rejected"} as ${identity.id.slice(0, 20)}…` : `Refused: ${JSON.stringify(res.error)}`;
  } catch (err) {
    resultEl.textContent = `Signing failed: ${err.message}`;
  }
}

async function replayVerify(port, token, runId, resultEl) {
  resultEl.textContent = "Asking helmd to re-execute the preceding step…";
  const pendingRes = await call("/ha/pending", { port, token });
  const held = pendingRes.ok ? pendingRes.data.pending.find((p) => p.run_id === runId) : null;
  if (!held) {
    resultEl.textContent = "Run is no longer held — nothing to replay against.";
    return;
  }
  // The gated step is held BEFORE running; replay-verify re-executes the
  // step immediately PRECEDING it (the artifact actually under review).
  if (!held.precedingStepId?.startsWith("nodes:")) {
    resultEl.textContent = "Replay-verify only supports a preceding \"nodes\" step.";
    return;
  }
  const res = await call("/ha/replay", { port, token, method: "POST", body: { run_id: runId, step_id: held.precedingStepId } });
  resultEl.textContent = res.ok
    ? `Replay ${res.data.matched ? "MATCHED" : "did NOT match"} — countersignature stored (replay_verified: ${res.data.matched}).`
    : `Replay failed: ${JSON.stringify(res.error)}`;
}

async function resumeRun(port, token, runId, resultEl) {
  resultEl.textContent = "Resuming…";
  const res = await call("/run/resume", { port, token, method: "POST", body: { run_id: runId } });
  resultEl.textContent = res.ok ? `Run is now: ${res.data.state}` : `Resume refused: ${JSON.stringify(res.error)}`;
}

// HELM-MAKERCHECKER-BUILD-SPEC.md MC-1.2: the maker's explicit signing act.
// Signs entirely in-browser (signBundleDigest) and submits for server-side
// verification (POST /ha/maker-sign) — helmd never mints this on the
// maker's behalf.
async function signAsMaker(port, token, subjectHash, resultEl) {
  resultEl.textContent = "Signing as maker in browser…";
  try {
    const identity = await loadOrCreateBrowserIdentity();
    const signature = await signBundleDigest(identity, subjectHash);
    const res = await call("/ha/maker-sign", { port, token, method: "POST", body: { subject_hash: subjectHash, maker_signature: { ...signature, attester_kind: "human" } } });
    resultEl.textContent = res.ok ? `Signed as maker: ${identity.id.slice(0, 20)}…` : `Refused: ${JSON.stringify(res.error)}`;
  } catch (err) {
    resultEl.textContent = `Signing failed: ${err.message}`;
  }
}

// MC-4: the checker signs with their OWN browser-held key over the subject
// digest — this only succeeds against the SAME browser profile that is
// distinct from the maker (MC-1 refuses same-identity server-side). The
// two-different-machines case is the export/import flow below, not this
// button.
async function countersign(port, token, subjectHash, resultEl) {
  resultEl.textContent = "Countersigning in browser…";
  try {
    const identity = await loadOrCreateBrowserIdentity();
    const signature = await signBundleDigest(identity, subjectHash);
    const countersignature = { role: "checker", identity: { id: identity.id }, signature, signed_at: new Date().toISOString(), attester_kind: "human" };
    const res = await call("/ha/countersign", { port, token, method: "POST", body: { subject_hash: subjectHash, countersignature } });
    resultEl.textContent = res.ok ? `Countersigned as: ${identity.id.slice(0, 20)}…` : `Refused: ${JSON.stringify(res.error)}`;
  } catch (err) {
    resultEl.textContent = `Countersigning failed: ${err.message}`;
  }
}

// MC-5: the transfer half — a countersignature signed on a DIFFERENT
// machine/browser (no helmd of its own reachable, or none at all) arrives
// here as a pasted, self-contained JSON blob and is submitted for
// verification exactly like a locally-produced one.
async function importCountersignature(port, token, subjectHash, blobText, resultEl) {
  let parsed;
  try {
    parsed = JSON.parse(blobText);
  } catch {
    resultEl.textContent = "That doesn't parse as JSON.";
    return;
  }
  const body = { subject_hash: parsed.subject_hash ?? subjectHash, countersignature: parsed.countersignature ?? parsed };
  resultEl.textContent = "Submitting imported countersignature…";
  const res = await call("/ha/countersign", { port, token, method: "POST", body });
  resultEl.textContent = res.ok ? "Imported countersignature accepted." : `Refused: ${JSON.stringify(res.error)}`;
}

function wireActions(root, port, token, rerender) {
  root.querySelectorAll(".approve-btn, .reject-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const { run, subject, role } = btn.dataset;
      const resultEl = root.querySelector(`#ha-result-${CSS.escape(run)}`);
      await submitDecision(port, token, { runId: run, subjectHash: subject, role, decision: btn.classList.contains("approve-btn") ? "approve" : "reject" }, resultEl);
    });
  });
  root.querySelectorAll(".replay-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const resultEl = root.querySelector(`#ha-result-${CSS.escape(btn.dataset.run)}`);
      await replayVerify(port, token, btn.dataset.run, resultEl);
    });
  });
  root.querySelectorAll(".resume-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const resultEl = root.querySelector(`#ha-result-${CSS.escape(btn.dataset.run)}`);
      await resumeRun(port, token, btn.dataset.run, resultEl);
      await rerender();
    });
  });
  root.querySelectorAll(".maker-sign-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const resultEl = btn.closest(".makerchecker-detail").querySelector(".ha-result");
      await signAsMaker(port, token, btn.dataset.subject, resultEl);
      await rerender();
    });
  });
  root.querySelectorAll(".countersign-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const resultEl = btn.closest(".makerchecker-detail").querySelector(".ha-result");
      await countersign(port, token, btn.dataset.subject, resultEl);
      await rerender();
    });
  });
  root.querySelectorAll(".import-countersign-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const detail = btn.closest(".makerchecker-detail");
      const resultEl = detail.querySelector(".ha-result");
      const blobText = detail.querySelector(".import-blob").value;
      await importCountersignature(port, token, btn.dataset.subject, blobText, resultEl);
      await rerender();
    });
  });
}

export async function renderReview(root, { port, token } = {}) {
  if (!port || !token) {
    root.innerHTML = `
      <p class="empty-state">helmd isn't paired yet. Pair a browser tab (see Status) to see runs held at a §27 accountability gate.</p>`;
    return;
  }

  root.innerHTML = `<p aria-live="polite">Checking helmd for pending accountability gates…</p>`;
  const pending = await fetchWithFallback("/ha/pending", { port, token });

  const blocked = classifyBlockedState(pending);
  if (blocked) {
    root.innerHTML = blockedStateHtml(blocked, {
      port,
      status: pending.status,
      route: pending.route,
      body: blocked === "too-old"
        ? "helmd answered, but the accountability-gate queue isn't part of this version of Helm yet."
        : "Helm is running, but this tab can't reach the accountability-gate queue right now.",
    });
    return;
  }

  const items = pending.data?.pending ?? [];
  const identity = await loadOrCreateBrowserIdentity();

  if (!items.length) {
    root.innerHTML = `
      <p class="empty-state">Nothing is waiting on a human right now. A run pauses here when its pack declares a step that needs a second person to sign off — for example a payment above a threshold, or a change that two people must independently approve before it continues.</p>
      <p class="empty-state">Your local approver identity: <code>${esc(identity.id)}</code></p>`;
    return;
  }

  const slots = await Promise.all(
    items.map(async (item) => {
      const res = await call(`/ha/slot?subject_hash=${encodeURIComponent(item.subjectHash)}`, { port, token });
      return res.ok ? res.data.slot : null;
    })
  );

  root.innerHTML = `
    <p class="empty-state">Your local approver identity: <code>${esc(identity.id)}</code> — signed in this browser, never sent to helmd.</p>
    <div class="card-grid">
      ${items.map((item, i) => pendingCard(item, identity.id, slots[i])).join("")}
    </div>`;

  wireActions(root, port, token, () => renderReview(root, { port, token }));
}
