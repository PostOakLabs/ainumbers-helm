// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Matters view (HELM-MATTER-U1, HELM-MATTER-BUILD-SPEC.md §2). Renders the
// matter store HELM-MATTER-H1/H2 already ship over REST (GET/POST /matters,
// GET /matters/{id}, POST /matters/{id}/update, POST /matters/{id}/delete,
// GET /matters/{id}/export) — this view adds no write path of its own beyond
// the already-shipped read-only export download, matching the row's fence:
// list, open/closed filter, deadline surfacing, binding browser.
//
// LOAD-BEARING RULE (the row's own done-criteria, §2's bindings[].subject_
// kind description, same §26.6 trust-label discipline verify.mjs already
// applies to trust labels): external_reference is the ONLY binding kind that
// may point outside Helm's local sealed storage, and the ONLY one Helm has
// never verified. Every other kind (run, evidence_bundle, approval_record,
// attested_artifact) was checked to resolve against local storage before
// matter-store.mjs ever accepted it (§3). bindingKindBadge() below renders
// the real subject_kind text every time — never a generic "verified" — and
// gives external_reference a visually distinct color and an explicit "never
// verified by Helm" note, so a reader can never mistake one for the other.
import { fetchWithFallback, call } from "../api.mjs";
import { esc } from "../lib/esc.mjs";
import { blockedStateHtml, classifyBlockedState } from "../lib/blocked-state.mjs";

const BINDING_KIND_COPY = {
  run: "Resolves against a run recorded in Helm's local storage.",
  evidence_bundle: "Resolves against an evidence bundle registered in Helm's local storage.",
  approval_record: "Resolves against a §27 accountability record in Helm's local storage.",
  attested_artifact: "Resolves against an attested-artifact step recorded in Helm's local storage.",
  external_reference: "Points at content outside Helm. Hashed, but never verified by Helm against anything.",
};

// The one place a binding's kind becomes a badge — every rendering of a
// binding goes through this, so there is no second code path that could
// collapse external_reference into the same look as the four local kinds.
export function bindingKindBadge(kind) {
  const known = kind in BINDING_KIND_COPY;
  const dataKind = kind === "external_reference" ? "external" : known ? "local" : "unknown";
  const title = known ? BINDING_KIND_COPY[kind] : "Not one of the five recognized binding kinds.";
  return `<span class="binding-kind-badge" data-kind="${esc(dataKind)}" title="${esc(title)}">${esc(kind)}</span>`;
}

function shortHash(h) {
  return h && h.length > 20 ? `${h.slice(0, 14)}…${h.slice(-6)}` : h;
}

function shortId(id) {
  return id && id.length > 28 ? `${id.slice(0, 24)}…` : id;
}

function bindingRow(b) {
  const isExternal = b.subject_kind === "external_reference";
  return `
    <li class="binding-row" data-kind="${isExternal ? "external" : "local"}">
      ${bindingKindBadge(b.subject_kind)}
      <code class="verify-digest" title="${esc(b.subject_hash)}">${esc(shortHash(b.subject_hash))}</code>
      ${isExternal ? `<p class="field-row-note">Never verified by Helm — hashed only, not checked against anything Helm holds.</p>` : ""}
      ${b.note ? `<p class="field-row-note">${esc(b.note)}</p>` : ""}
    </li>`;
}

function partyRow(p) {
  return `<li>${esc(p.role)} — <code title="${esc(p.identity?.id)}">${esc(shortId(p.identity?.id))}</code></li>`;
}

function deadlineRow(d) {
  return `
    <li class="deadline-row" data-done="${!!d.done}">
      <strong>${esc(d.date)}</strong> — ${esc(d.action)}
      <span class="phase-stub-badge">${esc(d.type)}</span>
      <span class="field-row-note">source: ${esc(d.source)}</span>
      ${d.done ? `<span class="field-row-note">done${d.done_at ? ` — ${esc(d.done_at)}` : ""}</span>` : ""}
    </li>`;
}

// Open (done:false) first, each bucket ascending by date — an examiner asks
// about what's still open first, so that's what a reader sees first too. A
// missing/malformed date sorts last within its bucket rather than throwing.
export function sortDeadlines(deadlines) {
  const byDate = (a, b) => (a.date || "9999-99-99").localeCompare(b.date || "9999-99-99");
  const open = (deadlines ?? []).filter((d) => !d.done).sort(byDate);
  const done = (deadlines ?? []).filter((d) => d.done).sort(byDate);
  return [...open, ...done];
}

export function nextOpenDeadline(deadlines) {
  const [first] = sortDeadlines(deadlines).filter((d) => !d.done);
  return first ?? null;
}

function matterStatusBadge(status) {
  return `<span class="matter-status-badge" data-status="${esc(status)}">${esc(status)}</span>`;
}

export function matterCard(matter) {
  const deadlines = sortDeadlines(matter.deadlines);
  const next = nextOpenDeadline(matter.deadlines);
  const bindings = matter.bindings ?? [];
  const externalCount = bindings.filter((b) => b.subject_kind === "external_reference").length;
  const parties = matter.parties ?? [];

  const nextLine = next
    ? `<p class="field-row-note">Next open deadline: <strong>${esc(next.date)}</strong> — ${esc(next.action)}</p>`
    : `<p class="field-row-note">No open deadlines on this matter.</p>`;

  const bindingsMixNote = externalCount
    ? `<p class="field-row-note">${externalCount} of ${bindings.length} binding${bindings.length === 1 ? "" : "s"} ${externalCount === 1 ? "is" : "are"} external_reference — hashed but never verified by Helm. The rest resolve against Helm's own local storage.</p>`
    : "";

  return `
    <section class="card matter-card" aria-labelledby="matter-${esc(matter.matter_id)}" data-status="${esc(matter.status)}">
      <h3 id="matter-${esc(matter.matter_id)}">${matterStatusBadge(matter.status)} <code>${esc(matter.matter_id)}</code></h3>
      <dl>
        <div class="field-row"><dt>Entity</dt><dd><code>${esc(matter.entity?.id)}</code>${matter.entity?.lei ? ` (LEI ${esc(matter.entity.lei)})` : ""}</dd></div>
        <div class="field-row"><dt>Created</dt><dd>${esc(matter.created_at)}</dd></div>
        <div class="field-row"><dt>Updated</dt><dd>${esc(matter.updated_at)}</dd></div>
      </dl>
      ${nextLine}
      ${matter.narrative ? `<p class="field-row-note">${esc(matter.narrative)}</p>` : ""}
      ${parties.length ? `<h4>Parties</h4><ul>${parties.map(partyRow).join("")}</ul>` : ""}
      <h4>Deadlines${deadlines.length ? ` (${deadlines.length})` : ""}</h4>
      ${deadlines.length ? `<ul class="deadline-list">${deadlines.map(deadlineRow).join("")}</ul>` : `<p class="empty-state">No deadlines recorded on this matter.</p>`}
      <h4>Bindings${bindings.length ? ` (${bindings.length})` : ""}</h4>
      ${bindings.length ? `<ul class="binding-list">${bindings.map(bindingRow).join("")}</ul>` : `<p class="empty-state">No bindings recorded on this matter yet.</p>`}
      ${bindingsMixNote}
      ${matter.status === "closed" ? `
        <button type="button" class="secondary matter-export-btn" data-matter="${esc(matter.matter_id)}">Download closeout export</button>
        <p class="matter-export-result" id="matter-export-result-${esc(matter.matter_id)}" role="status" aria-live="polite"></p>` : ""}
    </section>`;
}

// "Open" = not closed (intake or working) — the row's own filter language.
// A matter can legally close with open deadlines still on it (§2), so this
// is purely about matter.status, never about whether deadlines remain.
export function filterMatters(matters, filter) {
  if (filter === "open") return matters.filter((m) => m.status !== "closed");
  if (filter === "closed") return matters.filter((m) => m.status === "closed");
  return matters;
}

function filterBarHtml(active) {
  const options = [
    ["all", "All"],
    ["open", "Open"],
    ["closed", "Closed"],
  ];
  return `<div class="button-row" role="group" aria-label="Filter matters">
    ${options.map(([val, label]) => `<button type="button" class="matter-filter-btn${val === active ? "" : " secondary"}" data-filter="${val}" aria-pressed="${val === active}">${label}</button>`).join("")}
  </div>`;
}

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

// Pure read of the already-shipped GET /matters/{id}/export (HELM-MATTER-H2)
// — never assembles or signs anything itself. Downloads the signed
// bundle-of-bundles the daemon persisted at closeout, which is where the
// external_reference "hashed but never verified" reasoning shows up again,
// per-binding, in matter-store.mjs's own exportBindingArtifact().
function wireExportButtons(root, port, token) {
  root.querySelectorAll(".matter-export-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const matterId = btn.dataset.matter;
      const resultEl = root.querySelector(`#matter-export-result-${CSS.escape(matterId)}`);
      resultEl.textContent = "Fetching export…";
      const res = await call(`/matters/${encodeURIComponent(matterId)}/export`, { port, token });
      if (!res.ok) {
        resultEl.textContent = res.status === 404 ? "No closeout export recorded for this matter yet." : "helmd unreachable — export not fetched.";
        return;
      }
      downloadBlob(`matter-${matterId}-export.json`, JSON.stringify(res.data.export, null, 2), "application/json");
      resultEl.textContent = "Downloaded.";
    });
  });
}

export async function renderMatters(root, { port, token } = {}) {
  // Defense in depth alongside app.mjs's shell-level pairing gate (same
  // pattern as review.mjs) — this view is never reached unpaired in normal
  // use since "matters" is requiresPairing: true in tab-meta.mjs, but a
  // direct call (or a future requiresPairing change) still degrades cleanly.
  if (!port || !token) {
    root.innerHTML = `<p class="empty-state">helmd isn't paired yet. Pair a browser tab (see Status) to see matters recorded on this computer.</p>`;
    return;
  }

  root.innerHTML = `<p aria-live="polite">Checking helmd for matters…</p>`;
  const result = await fetchWithFallback("/matters", { port, token });

  const blocked = classifyBlockedState(result);
  if (blocked) {
    root.innerHTML = blockedStateHtml(blocked, {
      port,
      status: result.status,
      route: result.route,
      body:
        blocked === "too-old"
          ? "helmd answered, but matters aren't part of this version of Helm yet."
          : "Helm is running, but this tab can't reach the matter store right now.",
    });
    return;
  }

  const matters = result.data?.matters ?? [];
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";

  let filter = "all";

  function renderList() {
    const visible = filterMatters(matters, filter);
    const listHtml = visible.length
      ? `<div class="card-grid">${visible.map(matterCard).join("")}</div>`
      : `<p class="empty-state">${matters.length ? "No matters match this filter." : "No matters recorded yet. Matters are created through Helm's local API or an MCP-connected agent — for example, a workflow pack or connected tool opening one for an exam or filing."}</p>`;
    const slot = root.querySelector("#matters-list-slot");
    if (slot) slot.innerHTML = listHtml;
    wireExportButtons(root, port, token);
  }

  root.innerHTML = `
    ${staleBadge ? `<p class="view-subtitle">${staleBadge}</p>` : ""}
    <section class="card" aria-labelledby="matters-filter-heading">
      <h3 id="matters-filter-heading">Matters (${matters.length})</h3>
      ${filterBarHtml(filter)}
    </section>
    <div id="matters-list-slot"></div>`;

  root.querySelectorAll(".matter-filter-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      filter = btn.dataset.filter;
      root.querySelectorAll(".matter-filter-btn").forEach((b) => {
        const isActive = b === btn;
        b.classList.toggle("secondary", !isActive);
        b.setAttribute("aria-pressed", String(isActive));
      });
      renderList();
    });
  });

  renderList();
}
