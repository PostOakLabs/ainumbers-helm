// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX2-B-TABMETA (HELM-UX-BUILD-SPEC.md §12): the ONLY place a tab's
// identity is written. app.mjs generates <nav> and the #view-header from
// this array instead of the three unsynchronised lists §12.1 found (VIEWS,
// STATIC_VIEWS, hand-written <nav> in helm.html). §12.6 final IA (added in
// HELM-UX2-D-VIEWS): Home standalone first · Build [Choose, Canvas, Connect]
// · Execute [Run, Review, Verify] · Operate [Operate, Register, Deadlines,
// Learn]. Adding an id here with no matching VIEWS entry fails the §12.5
// gate by design (§12.2: requiresPairing has no default, and neither does
// view existence).
// HELM-UX2-J-AGENTS-SLOT (§19): "agents" is a RESERVED, DISABLED slot — no
// matching VIEWS entry, no route, rendered as a non-link nav item (see
// generateNav in app.mjs). tab-meta.test.mjs excludes `disabled: true` tabs
// from the TABS/VIEWS parity check for exactly this reason. The engine
// (HELM-H9) is date-gated before 2026-07-28; do not remove `disabled` or add
// a view until that row ships.
export const TABS = [
  { id: "home", label: "Home", group: "Home", intro: "What Helm is, and what to do first.", requiresPairing: false },
  { id: "choose", label: "Choose", group: "Build", intro: "Pick the workflow you want to run, from ready-made templates or your own packs.", requiresPairing: true },
  { id: "canvas", label: "Canvas", group: "Build", intro: "See exactly what a workflow will do, step by step, before you run it.", requiresPairing: true },
  { id: "connect", label: "Connect", group: "Build", intro: "Give a workflow access to the services it needs, one scope at a time.", requiresPairing: true },
  { id: "run", label: "Run", group: "Execute", intro: "Start a workflow and watch each step as it happens.", requiresPairing: true },
  { id: "review", label: "Review", group: "Execute", intro: "Sign off on runs that are waiting for a person before they can continue.", requiresPairing: true },
  { id: "verify", label: "Verify", group: "Execute", intro: "Check an evidence file's signatures and hashes, with no network connection.", requiresPairing: false },
  { id: "operate", label: "Operate", group: "Operate", intro: "Check how Helm is running on this computer, and take a backup.", requiresPairing: true },
  { id: "register", label: "Register", group: "Operate", intro: "Produce the model-risk register entry and validation cards for a workflow.", requiresPairing: true },
  { id: "deadlines", label: "Deadlines", group: "Operate", intro: "Regulatory dates that matter, and which of your workflows cover them.", requiresPairing: false },
  { id: "learn", label: "Learn", group: "Operate", intro: "How Helm works, how to fix a connection, and where the standard is written down.", requiresPairing: false },
  { id: "agents", label: "Agents / MCP", group: "Agents / MCP", intro: "Connect your own agent or MCP client to Helm. Not available yet.", requiresPairing: false, disabled: true },
];
