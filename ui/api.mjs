// Loopback API client for helmd. D8: bearer token on every call, no PII in
// URLs. Dormant-state discipline: a failed live call falls back to the last
// cached response with an explicit stale flag — never silently invents state
// the daemon never asserted.
const TOKEN_KEY = "helm.token";
const FP_KEY = "helm.fp";
const PORT_KEY = "helm.port";
const CACHE_PREFIX = "helm.cache.";

// Pure — no browser globals — so it's unit-testable under node:test.
export function parseTokenFromHash(hash) {
  const m = /(?:^|[#&])token=([^&]+)/.exec(hash || "");
  return m ? decodeURIComponent(m[1]) : null;
}

// P3-D9: the pairing link also carries a single-use nonce alongside the
// durable token — see hub/token.mjs for why they're separate values.
export function parsePairFromHash(hash) {
  const m = /(?:^|[#&])pair=([^&]+)/.exec(hash || "");
  return m ? decodeURIComponent(m[1]) : null;
}

// R15-F1 fix: the daemon identity-key fingerprint, delivered ONLY via this
// same trusted pairing link (only real helmd mints it — see token.mjs
// pairingUrl). Pinned for the session so a later /pair/challenge response
// can be checked against it, never trusted on self-consistency alone.
export function parseFpFromHash(hash) {
  const m = /(?:^|[#&])fp=([^&]+)/.exec(hash || "");
  return m ? decodeURIComponent(m[1]) : null;
}

export function isCacheStale(atIso, maxAgeMs) {
  const at = Date.parse(atIso);
  if (Number.isNaN(at)) return true;
  return Date.now() - at > maxAgeMs;
}

// P3-D9: scrub happens before this function returns to its caller, which in
// boot() is the very first statement executed — the token/nonce never
// survive to a second paint or a copyable address bar. Returns both values;
// callers redeem the pair nonce with a best-effort, non-blocking call (a
// failed redeem — e.g. an already-used link — must never lock the caller
// out, since it already holds the durable token in hand).
export function readTokenFromLocation(loc = location, hist = history) {
  const token = parseTokenFromHash(loc.hash);
  const pair = parsePairFromHash(loc.hash);
  const fp = parseFpFromHash(loc.hash);
  if (token || pair || fp) hist.replaceState(null, "", loc.pathname + loc.search);
  return { token, pair, fp };
}

export function loadToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}
export function saveToken(token) {
  sessionStorage.setItem(TOKEN_KEY, token);
}
export function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
}

// Pinned once per pairing, cleared alongside the token on unpair — a fresh
// pair (fresh fp=) is required after clearToken() rather than trusting a
// stale pin from a previous install/daemon.
export function loadFp() {
  return sessionStorage.getItem(FP_KEY);
}
export function saveFp(fp) {
  sessionStorage.setItem(FP_KEY, fp);
}
export function clearFp() {
  sessionStorage.removeItem(FP_KEY);
}

export function loadPort() {
  const stored = Number(localStorage.getItem(PORT_KEY));
  return Number.isInteger(stored) && stored > 0 ? stored : 4173;
}
export function savePort(port) {
  localStorage.setItem(PORT_KEY, String(port));
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

export async function call(path, { port, token, method = "GET", body: reqBody, timeoutMs = 3000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    if (reqBody !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers,
      body: reqBody !== undefined ? JSON.stringify(reqBody) : undefined,
      signal: controller.signal,
    });
    const body = await safeJson(res);
    if (!res.ok) return { ok: false, status: res.status, error: body };
    return { ok: true, status: res.status, data: body };
  } catch (err) {
    return { ok: false, status: 0, error: { network: err.message } };
  } finally {
    clearTimeout(timer);
  }
}

// Non-JSON GET (e.g. a ?format=html export) — same auth/timeout handling as
// call(), but returns raw text instead of parsing JSON. No cache fallback:
// downloadable exports are a one-shot action, not a page that needs a stale
// state to degrade into.
export async function callText(path, { port, token, timeoutMs = 5000 } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal: controller.signal,
    });
    const text = await res.text();
    if (!res.ok) return { ok: false, status: res.status, error: text };
    return { ok: true, status: res.status, text };
  } catch (err) {
    return { ok: false, status: 0, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

function cacheGet(path) {
  const raw = localStorage.getItem(CACHE_PREFIX + path);
  return raw ? JSON.parse(raw) : null;
}
function cacheSet(path, data) {
  localStorage.setItem(CACHE_PREFIX + path, JSON.stringify({ data, at: new Date().toISOString() }));
}

// Three outcomes: live (fresh data, daemon answered), stale (cached data, a
// prior live call succeeded, this one didn't), missing (never heard from the
// daemon on this path — nothing to show).
export async function fetchWithFallback(path, opts) {
  const res = await call(path, opts);
  if (res.ok) {
    cacheSet(path, res.data);
    return { state: "live", data: res.data };
  }
  const cached = cacheGet(path);
  if (cached) return { state: "stale", data: cached.data, at: cached.at };
  if (res.status === 404) return { state: "unavailable", error: res.error };
  return { state: "missing", error: res.error };
}
