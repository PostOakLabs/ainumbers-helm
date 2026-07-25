// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Single HTML-escaping helper for every ui/ template. Escapes all 5 chars
// that matter for both text-node and quoted-attribute contexts — & < > " ' —
// a 3-char (&<>-only) escaper leaves attribute-breakout live (found by phil,
// HELM-UX-BUILD-SPEC.md §16.1: the ui/views/canvas.mjs `escapeHtml` dropped
// quotes, which is exactly the gap `ui/views/connect.mjs`'s unescaped
// `connectorCard` template needed closed). Every other ui/lib copy of this
// function must import from here instead of redefining it — lint/lint.mjs
// gates redefinition.
export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
