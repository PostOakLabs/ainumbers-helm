// Company-profile config URL (HELM-P4-J1, Swagger-UI pattern). An embedder
// hosts a static JSON file at any https:// URL (or S3/GitHub Pages/intranet
// — no backend of ours involved) and points the app at it via `?config=`
// once; the URL itself then persists as a saved per-browser setting so
// future visits (and `helmd open`, which never carries the query string)
// keep restyling/retemplating without it.
//
// Config is DATA never code: this module only ever (a) fetches the URL as
// JSON — never eval'd, never inserted as HTML, (b) copies string values onto
// CSS custom properties via style.setProperty (not innerHTML, not a <style>
// text node built by concatenation), and (c) passes relay_url through the
// existing anchor-browser.mjs relay-base override, which still runs the full
// TimeStampToken messageImprint check against an untrusted relay — a hostile
// config can redirect where the DER bytes go, not what gets trusted as an
// anchor.
//
// Failure is always graceful: an unreachable host, a non-200, a non-JSON
// body, or a shape that fails schema validation all just skip application
// and leave the app on defaults — never a blocked render, never a thrown
// error out of initCompanyProfile().
import { validate } from "../vendored/schema-validator.mjs";
import COMPANY_PROFILE_SCHEMA from "../vendored/schemas/company_profile.schema.mjs";
import { setRelayBaseOverride } from "./anchor-browser.mjs";

const CONFIG_URL_KEY = "helm.companyProfile.url";
const BRAND_PROP_RE = /^--[a-z][a-z0-9-]*$/;

export function parseConfigUrlFromQuery(search = location.search) {
  const raw = new URLSearchParams(search).get("config");
  return raw && /^https:\/\//.test(raw) ? raw : null;
}

export function loadSavedConfigUrl() {
  return localStorage.getItem(CONFIG_URL_KEY);
}
export function saveConfigUrl(url) {
  localStorage.setItem(CONFIG_URL_KEY, url);
}
export function clearConfigUrl() {
  localStorage.removeItem(CONFIG_URL_KEY);
}

// Bare fetch, no daemon/port involved — the config host is whatever the
// embedder chose, unrelated to loopback helmd. timeoutMs keeps a stalled
// third-party host from hanging first paint.
export async function fetchCompanyProfile(url, { timeoutMs = 5000, fetchImpl = fetch } = {}) {
  if (!/^https:\/\//.test(url)) return { ok: false, error: "config url must be https://" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { signal: controller.signal, headers: { Accept: "application/json" } });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    let data;
    try {
      data = await res.json();
    } catch {
      return { ok: false, error: "response is not valid JSON" };
    }
    const errs = validate(COMPANY_PROFILE_SCHEMA, data);
    if (errs.length) return { ok: false, error: `schema: ${errs[0]}` };
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: err.name === "AbortError" ? "timed out" : err.message };
  } finally {
    clearTimeout(timer);
  }
}

// Only recognized CSS custom-property keys are applied — an arbitrary key in
// a hostile config just gets silently dropped, never becomes a new
// stylesheet rule or selector.
export function applyBranding(branding) {
  if (!branding || typeof branding !== "object") return;
  for (const [key, value] of Object.entries(branding)) {
    if (BRAND_PROP_RE.test(key) && typeof value === "string") {
      document.documentElement.style.setProperty(key, value);
    }
  }
}

export function getFeaturedTemplates(profile) {
  return Array.isArray(profile?.templates) ? profile.templates : null;
}

export function getPinnedKernelVersions(profile) {
  return profile?.pinned_kernel_versions && typeof profile.pinned_kernel_versions === "object"
    ? profile.pinned_kernel_versions
    : null;
}

let activeProfile = null;
export function getActiveCompanyProfile() {
  return activeProfile;
}

// Called once at boot. Resolution order: `?config=` (and it wins over, then
// overwrites, any saved setting — that's how a link retargets a shared
// device) falls back to the saved setting from a prior visit. Neither
// present = no-op, plain Helm.
export async function initCompanyProfile({ locationObj = location } = {}) {
  const fromQuery = parseConfigUrlFromQuery(locationObj.search);
  const url = fromQuery || loadSavedConfigUrl();
  if (!url) return null;

  const result = await fetchCompanyProfile(url);
  if (!result.ok) {
    console.warn(`company-profile: ${url} — ${result.error} (falling back to defaults)`);
    return null;
  }

  if (fromQuery) saveConfigUrl(fromQuery);
  activeProfile = result.data;
  applyBranding(result.data.branding);
  if (typeof result.data.relay_url === "string") setRelayBaseOverride(result.data.relay_url);
  return result.data;
}
