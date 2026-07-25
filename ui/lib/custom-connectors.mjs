// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// User-added custom connector contracts (HELM-UX2-G-IMPORT,
// HELM-UX-BUILD-SPEC.md §16.3-§16.8). Parse/validate/store logic lives here,
// separate from ui/views/connect.mjs's DOM wiring, so §16.4's three distinct
// messages (parse failure / schema failure / success) and §16.5's refusals
// are unit-testable without a DOM.
import { loadContractFromObject } from "./connector-browser.mjs";

const STORAGE_KEY = "helm.custom.connectors";

// hub/connectors/*.contract.json ids (daemon-servable even when the daemon
// is unreachable right now) + the three browser-native providers wired in
// ui/views/connect.mjs (its TOKEN_REFS keys) — none of these may be silently
// widened by a user-added contract (§16.5's "colliding with a daemon-served
// or built-in connector" refusal). Daemon ids actually seen live are added
// on top of this at call time (renderConnect passes its fetched entries).
export const BUILTIN_CONNECTOR_IDS = Object.freeze([
  "google-drive.fetch", "http.send", "inbound-webhook", "smtp.send",
  "microsoft", "google", "github",
]);

export function loadCustomConnectors() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function saveCustomConnectors(list) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(list));
}

// Parses untrusted text into a value whose own top-level "__proto__" (if
// any) is an ordinary data property, never a live prototype link. JSON.parse
// itself never triggers the __proto__ accessor (a parsed "__proto__" key
// lands as a normal own property) — the danger is downstream code spreading
// that parsed object onto a plain object literal, which WOULD trigger the
// setter. Re-homing every key onto a null-prototype target here means there
// is no prototype accessor left for any later spread/Object.assign to hit,
// so callers never need to reason about it again (§16.5).
function parseJson(text) {
  const parsed = JSON.parse(text);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return parsed;
  return Object.assign(Object.create(null), parsed);
}

// Step 1+2 of §16.4 (validate → preview): parse, then collision-check, then
// schema-check. Each failure mode returns its own distinct `stage`/message —
// never conflate "couldn't parse" with "parsed fine but invalid contract".
// A schema failure refuses the WHOLE contract; there is no partial accept.
export async function validateCandidate(text, { knownIds = [] } = {}) {
  let candidate;
  try {
    candidate = parseJson(text);
  } catch (err) {
    return { stage: "parse", ok: false, message: `Couldn't parse that as JSON: ${err.message}` };
  }

  const known = new Set([...BUILTIN_CONNECTOR_IDS, ...knownIds]);
  if (candidate && typeof candidate === "object" && typeof candidate.connector_id === "string" && known.has(candidate.connector_id)) {
    return {
      stage: "collision",
      ok: false,
      message: `"${candidate.connector_id}" is already a built-in or daemon-served connector id — a custom import can't reuse it.`,
    };
  }

  try {
    const { contract, contractDigest } = await loadContractFromObject(candidate);
    return { stage: "preview", ok: true, contract, contractDigest };
  } catch (err) {
    return { stage: "schema", ok: false, message: `That contract failed schema validation: ${err.message}` };
  }
}

// Step 3 of §16.4 (confirm): a SEPARATE explicit call from validateCandidate
// — validating and previewing never adds anything by themselves. Detects a
// same-id-different-digest collision instead of silently overwriting it
// (§16.7's "a later silent edit under the same id is detectable").
export function addCustomConnector({ contract, contractDigest }) {
  const list = loadCustomConnectors();
  const existing = list.find((e) => e.contract.connector_id === contract.connector_id);
  if (existing) {
    throw new Error(
      existing.contractDigest === contractDigest
        ? `"${contract.connector_id}" is already added.`
        : `"${contract.connector_id}" is already added with a DIFFERENT contract (digest changed) — remove the existing one first if you meant to replace it.`
    );
  }
  list.push({ contract, contractDigest, addedAt: new Date().toISOString() });
  saveCustomConnectors(list);
  return list;
}

export function removeCustomConnector(connectorId) {
  saveCustomConnectors(loadCustomConnectors().filter((e) => e.contract.connector_id !== connectorId));
}

// §16.6: the only mitigation for look-alike hosts is presentation — no
// validator catches `api.rnicrosoft.com`. Splits a host into its full form
// (rendered monospace by the caller via <code>) and its registrable domain
// (rendered emphasised, never truncated). The last-two-labels heuristic is a
// zero-dep approximation of the public suffix list — it under-splits on
// multi-part TLDs (e.g. "co.uk") but never OVER-emphasises past the real
// organization boundary, which is the direction that matters for spotting a
// look-alike. Also surfaces the Punycode form when the host contains
// non-ASCII (IDN homograph risk) — case-only normalization is excluded so an
// all-ASCII host with different casing is never mistaken for Punycode.
export function hostDisplayParts(host) {
  const labels = host.split(".");
  const registrable = labels.length >= 2 ? labels.slice(-2).join(".") : host;
  let punycode = null;
  if (/[^\x00-\x7F]/.test(host)) {
    try {
      const encoded = new URL(`https://${host}`).hostname;
      if (encoded !== host) punycode = encoded;
    } catch {
      punycode = null;
    }
  }
  return { host, registrable, punycode };
}
