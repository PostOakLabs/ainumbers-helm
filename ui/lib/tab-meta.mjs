// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX2-B-TABMETA (HELM-UX-BUILD-SPEC.md §12): the ONLY place a tab's
// identity is written. app.mjs generates <nav> and the #view-header from
// this array instead of the three unsynchronised lists §12.1 found (VIEWS,
// STATIC_VIEWS, hand-written <nav> in app.html). §12.6 final IA (added in
// HELM-UX2-D-VIEWS): Home standalone first · Build [Choose, Canvas, Connect]
// · Execute [Run, Review, Verify] · Status [Operate, Register, Deadlines,
// Learn] (group/tab labels renamed 2026-08-07, HELM-TABHELP-1 — Tim's nav
// naming ruling; ids/routes unchanged). Adding an id here with no matching VIEWS entry fails the §12.5
// gate by design (§12.2: requiresPairing has no default, and neither does
// view existence).
// HELM-AGENTS-TAB-3 (§19.5): "agents" is LIVE. HELM-H9 shipped (helm PR
// #156/#158) and the handshake was re-proven against a running helmd with a
// real MCP SDK client (initialize + a real-args tools/call, both completed)
// before this flag flipped — see this row's check-off for the transcript.
// requiresPairing: true because the tab's content needs the daemon; unpaired
// degrades to the §13 blocked state via ui/views/agents.mjs, same pattern as
// every other paired tab. tab-meta.test.mjs still excludes `disabled: true`
// tabs from the TABS/VIEWS parity check — that exclusion has no live user
// today but is covered by a fixture-based test so it doesn't silently rot
// before the next reserved slot needs it.
// HELM-MATTER-U1: "matters" joins Status, after Deadlines — the §12.6 IA
// line above records the 2026-08-07 naming ruling and isn't re-stated for
// every later addition; see this tab's own row for its history.
export const TABS = [
  { id: "home", label: "Home", group: "Home", intro: "What Helm is, and what to do first.", requiresPairing: false },
  { id: "choose", label: "Choose", group: "Build", intro: "Pick the workflow you want to run, from ready-made templates or your own packs.", requiresPairing: true },
  { id: "canvas", label: "Canvas", group: "Build", intro: "See exactly what a workflow will do, step by step, before you run it.", requiresPairing: true },
  { id: "connect", label: "Connect", group: "Build", intro: "Give a workflow access to the services it needs, one scope at a time.", requiresPairing: true },
  { id: "run", label: "Run", group: "Execute", intro: "Start a workflow and watch each step as it happens.", requiresPairing: true },
  { id: "review", label: "Review", group: "Execute", intro: "Sign off on runs that are waiting for a person before they can continue.", requiresPairing: true },
  { id: "verify", label: "Verify", group: "Execute", intro: "Check an evidence file's signatures and hashes, with no network connection.", requiresPairing: false },
  { id: "operate", label: "Status", group: "Status", intro: "Check how Helm is running on this computer, and take a backup.", requiresPairing: true },
  { id: "register", label: "Register", group: "Status", intro: "Produce the governance/EUC/change-control register entry and validation cards for a workflow — each kernel is one calculation step in the workflow.", requiresPairing: true },
  { id: "deadlines", label: "Deadlines", group: "Status", intro: "Regulatory dates that matter, and which of your workflows cover them.", requiresPairing: false },
  { id: "matters", label: "Matters", group: "Status", intro: "The exams, filings, and disputes you're tracking, with their deadlines and the evidence bound to each.", requiresPairing: true },
  { id: "learn", label: "Learn", group: "Status", intro: "How Helm works, how to fix a connection, and where the standard is written down.", requiresPairing: false },
  { id: "agents", label: "AI agents", group: "AI agents", intro: "Connect your own agent or MCP client to Helm.", requiresPairing: true },
];
