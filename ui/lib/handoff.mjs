// Detection + handoff primitives (HELM-P3-H6, P3-D3/D6/D9). Pure, portable
// functions — no module-scope browser globals — so a future hosted
// browser-mode app (P3-U2..U4, not built yet) can import this directly and
// it's fully unit-testable under node:test today. Every network call is a
// parameter (fetchImpl), never a bare `fetch` reference, so nothing here
// ever runs on its own: the caller decides WHEN (click-gated, never on
// page load) and provides the transport.

// UI-side counterpart to hub/server.mjs's SUPPORTED_API_VERSIONS. Kept as a
// literal, not an import — this module ships to a browser, hub/ ships to
// Node, and the two never share a bundler.
export const UI_API_VERSIONS = ["helm/1"];

export const DEFAULT_HELM_PORT = 4173;

// Builds the primary handoff target (P3-D3): a same-origin, top-level
// navigation URL. This is the ONLY handoff mechanism that works
// unconditionally — Safari (no LNA, no PNA), a Chrome managed profile with
// LNA denied, and a plain http fetch all still let a normal link navigate.
export function buildHandoffUrl(token, port = DEFAULT_HELM_PORT, pairNonce) {
  if (!token) throw new Error("buildHandoffUrl: token required");
  const pair = pairNonce ? `&pair=${pairNonce}` : "";
  return `http://127.0.0.1:${port}/#token=${token}${pair}`;
}

// Performs the handoff via TOP-LEVEL NAVIGATION, never window.open (P3-D3:
// popup blockers would eat it, and a popup's opener relationship trips
// Chrome's Cross-Origin-Opener-Policy on the daemon-served page). `nav`
// defaults to a real navigation function so callers don't have to know the
// DOM API; tests inject a spy instead.
export function navigateToHandoff(url, nav = (u) => { location.href = u; }) {
  nav(url);
}

// Detection probe states. "denied" and "absent" are both folded into clean
// browser mode by the caller — the distinction exists for diagnostics only,
// never for retrying or nagging the user.
export const PROBE_STATE = {
  DETECTED: "detected",
  DENIED: "denied",
  UNREACHABLE: "unreachable",
  UNEXPECTED: "unexpected", // something answered, but not helmd (port-squat signal)
};

// Click-gated LNA-wrapped detection probe (P3-D3). MUST be called only in
// response to an explicit user click — never on page load, never on a
// timer, never retried automatically. `fetchImpl` is injected so this stays
// testable without a real network stack; it must be the browser's `fetch`
// in production so `targetAddressSpace` is honored by Chrome's PNA check.
// AbortSignal.timeout ships everywhere Chrome/Firefox/Safari matter today,
// but falls back to a manual AbortController so an engine that lacks it
// still bounds the probe instead of hanging indefinitely (F13).
function timeoutSignal(timeoutMs) {
  if (typeof AbortSignal.timeout === "function") return AbortSignal.timeout(timeoutMs);
  const controller = new AbortController();
  setTimeout(() => controller.abort(new Error("probeDaemon: timed out")), timeoutMs);
  return controller.signal;
}

export async function probeDaemon({ port = DEFAULT_HELM_PORT, fetchImpl, timeoutMs = 2000 } = {}) {
  if (!fetchImpl) throw new Error("probeDaemon: fetchImpl required");
  let res;
  try {
    res = await fetchImpl(`http://127.0.0.1:${port}/version`, {
      targetAddressSpace: "loopback",
      signal: timeoutSignal(timeoutMs),
    });
  } catch (err) {
    // LNA denial, PNA preflight failure, and "nothing listening" all land
    // here as a plain fetch rejection in every browser that implements
    // this check — there is no reliable way to distinguish "denied" from
    // "absent" from script, and P3-D3 doesn't need to: both are clean
    // browser mode. Named DENIED for the common case; callers must not
    // branch behavior on this vs. UNREACHABLE.
    return { state: PROBE_STATE.DENIED, reason: String(err?.message || err) };
  }
  if (!res.ok) return { state: PROBE_STATE.UNREACHABLE, status: res.status };
  let body;
  try {
    body = await res.json();
  } catch {
    return { state: PROBE_STATE.UNEXPECTED };
  }
  if (typeof body?.daemon !== "string" || !Array.isArray(body?.api)) {
    return { state: PROBE_STATE.UNEXPECTED };
  }
  return { state: PROBE_STATE.DETECTED, daemon: body.daemon, api: body.api };
}

// Capability intersection (P3-D6): a hosted UI newer than the daemon is
// "degraded but working," never a hard failure. compatible=false only when
// there is NO shared api version at all — everything else degrades.
export function negotiateCapabilities(uiApiVersions, daemonApiVersions) {
  const shared = uiApiVersions.filter((v) => daemonApiVersions.includes(v));
  if (shared.length === 0) {
    return { compatible: false, degraded: true, sharedVersions: [], updateNudge: true };
  }
  const uiHasNewer = uiApiVersions.some((v) => !daemonApiVersions.includes(v));
  return {
    compatible: true,
    degraded: uiHasNewer,
    sharedVersions: shared,
    updateNudge: uiHasNewer,
  };
}
