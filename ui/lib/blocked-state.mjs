// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX2-C-BLOCKED (HELM-UX-BUILD-SPEC.md §13): one renderer for the THREE
// blocked/empty cases that can occur once a view is being served by helmd at
// all (§11.1 — there is no fourth "Helm isn't installed" case, because the
// page could not have loaded without helmd already serving it):
//   not-paired  — helmd is serving this page but this tab's token is
//                 missing/invalid (401/403), OR the request otherwise failed
//                 with no cached fallback (§11.1 admits no fourth bucket, so
//                 a stray network error folds in here too — the fix is the
//                 same "reconnect this tab" action either way).
//   too-old     — helmd answered but doesn't have this route yet (404).
//   empty       — helmd answered live/stale and there is genuinely nothing
//                 to show. Callers supply their own copy for this case
//                 (§13.6: it must teach, not report — generic wording here
//                 would just be a second bare sentence).
// §13.3: port/host/status/route go in a collapsed <details>, never the
// headline. §13.1: no bare failure sentence anywhere.
import { esc } from "./esc.mjs";

const KIND_COPY = {
  "not-paired": {
    heading: "Reconnect this tab",
    body: "Helm is running, but this browser tab's pairing token is missing, expired, or was rejected.",
    action: `Open helmd's pairing link again to reconnect this tab. If you don't have the link, use <a href="#/operate">Operate</a>'s advanced pairing form.`,
  },
  "too-old": {
    heading: "Not in this Helm version yet",
    body: "helmd answered, but the version of Helm running on this computer doesn't have this page yet.",
    action: "Update Helm, then reload this page.",
  },
};

// Announced to AT per §13.3 — the <details> element's native toggle already
// fires a DOM mutation, but a role="status" sibling keeps the summary text
// itself as the affordance rather than requiring a second discovery.
function technicalDetails(fields) {
  const rows = Object.entries(fields).filter(([, v]) => v !== undefined && v !== null && v !== "");
  if (!rows.length) return "";
  return `
    <details class="blocked-state-details">
      <summary>Technical details</summary>
      <dl>${rows.map(([k, v]) => `<div class="field-row"><dt>${esc(k)}</dt><dd><code>${esc(String(v))}</code></dd></div>`).join("")}</dl>
    </details>`;
}

// opts: { port, status, route, body, action, extra } — body/action override
// the generic copy (required for "empty"; optional for the other two).
// extra is raw HTML appended before the technical details (§13.5: canvas's
// file picker, choose's stale-cache list).
export function blockedStateHtml(kind, opts = {}) {
  const { port, status, route, body, action, extra = "" } = opts;
  const copy = KIND_COPY[kind] ?? {};
  const heading = copy.heading ?? "Not available right now";
  const bodyText = body ?? copy.body ?? "";
  const actionHtml = action ?? copy.action ?? "";
  return `
    <div class="blocked-state" data-kind="${esc(kind)}">
      <p class="blocked-state-heading">${heading}</p>
      <p class="blocked-state-body">${bodyText}</p>
      <p class="blocked-state-action">${actionHtml}</p>
      ${extra}
      ${technicalDetails({ route, "status code": status, port })}
    </div>`;
}

// Classifies a fetchWithFallback() result. Returns null when the result
// carries usable data (live/stale) — the caller renders content, not a
// blocked state, though it may still layer a stale badge on top.
export function classifyBlockedState(result) {
  if (result.state === "unavailable") return "too-old";
  if (result.state === "missing") return "not-paired";
  return null;
}
