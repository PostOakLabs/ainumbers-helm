// Dedicated fragment-free OAuth callback logic (HELM-P3-U4, P3-D5). Lives at
// its own static path (oauth-callback.html), separate from helm.html's
// hash-router, specifically so a provider's query-param redirect
// (?code=&state=) can never collide with the app's own #/view hash routing —
// mixing the two on one URL is the exact conflict P3-D5 calls out. Microsoft
// and Google's authorization-code flow both return code/state as QUERY
// params by default (not a hash fragment), which is what makes this
// separation possible.
//
// Kept as an importable module (not inline <script> logic) so the parsing
// and relay steps are unit-testable under node:test — an untestable inline
// script is exactly what the spec asks this WU to avoid.
export function parseCallbackParams(search) {
  const params = new URLSearchParams(search || "");
  const error = params.get("error");
  if (error) return { ok: false, error, errorDescription: params.get("error_description") };
  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) return { ok: false, error: "missing_code_or_state" };
  return { ok: true, code, state };
}

const RELAY_KEY = "helm.oauth.callback";

// Stashes the parsed result in sessionStorage — the ONLY thing this
// transient relay page ever touches (never localStorage, never the vault) —
// for the app to pick up after redirect. Scrubs the address bar via
// history.replaceState BEFORE navigating away, so the authorization code
// never lingers in visible/copyable history (same discipline as P3-D9's
// pairing-token scrub in ui/api.mjs's readTokenFromLocation).
export function relayAndRedirect({
  result,
  targetUrl,
  storage = sessionStorage,
  history = window.history,
  loc = window.location,
  navigate = (u) => { location.replace(u); },
}) {
  storage.setItem(RELAY_KEY, JSON.stringify(result));
  history.replaceState(null, "", loc.pathname);
  navigate(targetUrl);
}

// Called by the app (e.g. the Connect view) after being redirected back in.
// One-shot: the relayed value is removed on read so a page reload never
// replays a stale authorization code.
export function consumeRelayedResult(storage = sessionStorage) {
  const raw = storage.getItem(RELAY_KEY);
  if (!raw) return null;
  storage.removeItem(RELAY_KEY);
  return JSON.parse(raw);
}
