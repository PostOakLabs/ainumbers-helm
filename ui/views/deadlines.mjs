// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Deadlines view (HELM-UX2-D-VIEWS, HELM-UX-BUILD-SPEC.md §20): browser-only
// data, no daemon route yet (§20.1), requiresPairing: false.
//
// §20.2: this is deliberately NOT a copy of ainumbers.co/deadline-wall.html
// — that page's job is the full, source-cited regulatory record. Unpaired,
// this tab degrades to a short plain list pointing at that record. Paired,
// it adds the one thing the site cannot know: which of *your* workflow
// packs cover a regime, and what the daemon last reported about that pack.
// §20.3: until a daemon /deadlines route exists, coverage is derived from
// data the shell already fetches for Choose (/workflows) — a case-
// insensitive keyword match against each pack's name/outcome text. That is
// a heuristic, not a certified mapping, and the copy says so; it never
// claims a pack "covers" a regime it merely happens to mention.
import { fetchWithFallback } from "../api.mjs";
import { esc } from "../lib/esc.mjs";

// A small, deliberately reduced subset of the site's full Deadline Wall
// dataset (repo/deadline-wall.html) — regime/jurisdiction/date only, no
// citations. The full record with sources lives on the site; this list
// exists to drive the coverage match below, not to replace it.
const DEADLINES = [
  { id: "dora-register-of-information", regime: "DORA Register of Information (RoI)", jurisdiction: "EU", date: "2026-04-30", keywords: ["dora"] },
  { id: "nydfs-certification-of-compliance", regime: "NYDFS Cybersecurity Regulation (23 NYCRR 500) Certification", jurisdiction: "New York State, US", date: "2026-04-15", keywords: ["nydfs"] },
  { id: "ffiec-call-report-q2-2026", regime: "FFIEC Call Report (031/041/051)", jurisdiction: "US", date: "2026-07-30", keywords: ["ffiec", "call report"] },
  { id: "fr-y-9c", regime: "FR Y-9C Consolidated Financial Statements for Holding Companies", jurisdiction: "US", date: "2026-08-09", keywords: ["fr y-9c", "y-9c"] },
  { id: "pillar-two-gir", regime: "Pillar Two GloBE Information Return (GIR)", jurisdiction: "OECD / Global", date: "2026-06-30", keywords: ["pillar two", "globe", "gir"] },
  { id: "cyber-incident-banking-36h", regime: "Computer-Security Incident Notification (36-Hour Banking Agency Rule)", jurisdiction: "US", date: null, keywords: ["incident notification", "36-hour", "36 hour"] },
  { id: "sec-8k-item105-cyber", regime: "SEC Form 8-K Item 1.05 Material Cybersecurity Incident Disclosure", jurisdiction: "US", date: null, keywords: ["8-k", "item 1.05", "cyber"] },
  { id: "ctc-france-large", regime: "CTC e-invoicing/e-reporting — France, receipt (all) + issuance (large/ETI)", jurisdiction: "France", date: "2026-09-01", keywords: ["ctc", "e-invoic", "france"] },
  { id: "fedwire-iso20022-structured-address", regime: "Fedwire Funds Service — ISO 20022 structured postal address requirement", jurisdiction: "US", date: "2026-11-16", keywords: ["fedwire", "iso 20022", "iso20022"] },
];

function fmtDate(d) {
  return d ? d : "recurring / event-triggered — no single next date";
}

function plainRow(d) {
  return `<tr><td>${esc(d.regime)}</td><td>${esc(d.jurisdiction)}</td><td>${esc(fmtDate(d.date))}</td></tr>`;
}

function matchPack(deadline, packs) {
  return packs.find((p) => {
    const haystack = `${p.name ?? p.workflow_id ?? ""} ${p.outcome ?? ""}`.toLowerCase();
    return deadline.keywords.some((k) => haystack.includes(k));
  });
}

function coverageRow(d, packs) {
  const pack = matchPack(d, packs);
  const coverage = pack
    ? `<span class="stale-badge" role="status">covered by "${esc(pack.name ?? pack.workflow_id)}" — ${esc(pack.status ?? "status unknown")}</span>`
    : `<span class="empty-state">not covered by a workflow pack on this computer</span>`;
  return `<tr><td>${esc(d.regime)}</td><td>${esc(d.jurisdiction)}</td><td>${esc(fmtDate(d.date))}</td><td>${coverage}</td></tr>`;
}

const TABLE_HEAD_PLAIN = `<tr><th scope="col">Regime</th><th scope="col">Jurisdiction</th><th scope="col">Next date</th></tr>`;
const TABLE_HEAD_COVERAGE = `<tr><th scope="col">Regime</th><th scope="col">Jurisdiction</th><th scope="col">Next date</th><th scope="col">Coverage</th></tr>`;

const FULL_WALL_LINK = `<p class="field-row-note">This is a short list, not the full record. See the source-cited <a href="https://ainumbers.co/deadline-wall.html" rel="noopener">Deadline Wall</a> for citations, recurrence rules, and every regime it tracks.</p>`;

export async function renderDeadlines(root, { port, token }) {
  if (!token) {
    root.innerHTML = `
      <section class="card" aria-labelledby="deadlines-plain">
        <h3 id="deadlines-plain">Upcoming regulatory dates</h3>
        <p class="empty-state">This tab isn't paired with helmd, so it can't check which of your workflows cover these. Pair this tab to see coverage.</p>
        ${FULL_WALL_LINK}
        <table><thead>${TABLE_HEAD_PLAIN}</thead><tbody>${DEADLINES.map(plainRow).join("")}</tbody></table>
      </section>`;
    return;
  }

  root.innerHTML = `<p aria-live="polite">Checking your workflow packs…</p>`;
  const result = await fetchWithFallback("/workflows", { port, token });
  const packs = result.state === "live" || result.state === "stale" ? (result.data?.workflows ?? []) : [];
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";
  const noPacksNote = packs.length === 0 ? `<p class="empty-state">No workflow packs configured yet, so nothing here can show as covered — see <a href="#/choose">Choose</a>.</p>` : "";

  root.innerHTML = `
    <section class="card" aria-labelledby="deadlines-coverage">
      <h3 id="deadlines-coverage">Regulatory dates and your coverage</h3>
      <p class="field-row-note">Coverage is a name/outcome keyword match against your workflow packs — a starting point, not a certified mapping. Check the pack's own manifest on <a href="#/canvas">Canvas</a> before relying on it.</p>
      ${staleBadge ? `<p class="view-subtitle">${staleBadge}</p>` : ""}
      ${noPacksNote}
      ${FULL_WALL_LINK}
      <table><thead>${TABLE_HEAD_COVERAGE}</thead><tbody>${DEADLINES.map((d) => coverageRow(d, packs)).join("")}</tbody></table>
    </section>`;
}
