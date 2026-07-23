// Loopback API client for helmd. D8: bearer token on every call, no PII in
// URLs. Dormant-state discipline: a failed live call falls back to the last
// cached response with an explicit stale flag — never silently invents state
// the daemon never asserted.
const TOKEN_KEY = "helm.token";
const PORT_KEY = "helm.port";
const CACHE_PREFIX = "helm.cache.";

// Pure — no browser globals — so it's unit-testable under node:test.
export function parseTokenFromHash(hash) {
  const m = /(?:^|[#&])token=([^&]+)/.exec(hash || "");
  return m ? decodeURIComponent(m[1]) : null;
}

export function isCacheStale(atIso, maxAgeMs) {
  const at = Date.parse(atIso);
  if (Number.isNaN(at)) return true;
  return Date.now() - at > maxAgeMs;
}

export function readTokenFromLocation(loc = location, hist = history) {
  const token = parseTokenFromHash(loc.hash);
  if (token) hist.replaceState(null, "", loc.pathname + loc.search);
  return token;
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
