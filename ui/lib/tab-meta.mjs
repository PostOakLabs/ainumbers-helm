// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX2-B-TABMETA (HELM-UX-BUILD-SPEC.md §12): the ONLY place a tab's
// identity is written. app.mjs generates <nav> and the #view-header from
// this array instead of the three unsynchronised lists §12.1 found (VIEWS,
// STATIC_VIEWS, hand-written <nav> in helm.html). Home, Learn (help.mjs
// rename), and Deadlines join this array in HELM-UX2-D-VIEWS once their
// views exist — adding an id here with no matching VIEWS entry fails the
// §12.5 gate by design (§12.2: requiresPairing has no default, and neither
// does view existence).
export const TABS = [
  { id: "choose", label: "Choose", group: "Build", intro: "Pick the workflow you want to run, from ready-made templates or your own packs.", requiresPairing: true },
  { id: "canvas", label: "Canvas", group: "Build", intro: "See exactly what a workflow will do, step by step, before you run it.", requiresPairing: true },
  { id: "connect", label: "Connect", group: "Build", intro: "Give a workflow access to the services it needs, one scope at a time.", requiresPairing: true },
  { id: "run", label: "Run", group: "Execute", intro: "Start a workflow and watch each step as it happens.", requiresPairing: true },
  { id: "review", label: "Review", group: "Execute", intro: "Sign off on runs that are waiting for a person before they can continue.", requiresPairing: true },
  { id: "verify", label: "Verify", group: "Execute", intro: "Check an evidence file's signatures and hashes, with no network connection.", requiresPairing: false },
  { id: "operate", label: "Operate", group: "Operate", intro: "Check how Helm is running on this computer, and take a backup.", requiresPairing: true },
  { id: "register", label: "Register", group: "Operate", intro: "Produce the model-risk register entry and validation cards for a workflow.", requiresPairing: true },
  { id: "help", label: "Help", group: "Operate", intro: "What each tab does, and how to reconnect if pairing is lost.", requiresPairing: false },
];
