// Tests for the company-profile config URL loader (HELM-P4-J1). No real DOM
// or browser storage in node:test, so this stubs the minimal globals the
// module touches (localStorage, document.documentElement.style) — same
// zero-dep discipline as the rest of ui/lib, nothing pulled in for it.
import { test } from "node:test";
import assert from "node:assert/strict";

class FakeStorage {
  #map = new Map();
  getItem(k) { return this.#map.has(k) ? this.#map.get(k) : null; }
  setItem(k, v) { this.#map.set(k, String(v)); }
  removeItem(k) { this.#map.delete(k); }
}
globalThis.localStorage = new FakeStorage();

const styleProps = new Map();
globalThis.document = {
  documentElement: { style: { setProperty: (k, v) => styleProps.set(k, v) } },
};

const {
  parseConfigUrlFromQuery,
  loadSavedConfigUrl,
  saveConfigUrl,
  clearConfigUrl,
  fetchCompanyProfile,
  applyBranding,
  getFeaturedTemplates,
  getPinnedKernelVersions,
  getActiveCompanyProfile,
  initCompanyProfile,
} = await import("./company-profile.mjs");
const { currentRelayBase, setRelayBaseOverride } = await import("./anchor-browser.mjs");

const GOLDEN = {
  schema_version: 1,
  profile_name: "Acme Compliance",
  templates: ["pillar-two-provision", "cbcr-notification"],
  branding: { "--accent": "#7a1fd9" },
  relay_url: "https://anchor.acme-internal.example",
  pinned_kernel_versions: { "art-201": "1.4.0" },
};

test("parseConfigUrlFromQuery: reads https config= param", () => {
  assert.equal(parseConfigUrlFromQuery("?config=https%3A%2F%2Fexample.com%2Fp.json"), "https://example.com/p.json");
});

test("parseConfigUrlFromQuery: rejects non-https (data/javascript/http)", () => {
  assert.equal(parseConfigUrlFromQuery("?config=http://example.com/p.json"), null);
  assert.equal(parseConfigUrlFromQuery("?config=javascript:alert(1)"), null);
  assert.equal(parseConfigUrlFromQuery("?config=data:text/html,x"), null);
});

test("parseConfigUrlFromQuery: absent param returns null", () => {
  assert.equal(parseConfigUrlFromQuery(""), null);
  assert.equal(parseConfigUrlFromQuery("?other=1"), null);
});

test("saveConfigUrl/loadSavedConfigUrl/clearConfigUrl round-trip", () => {
  clearConfigUrl();
  assert.equal(loadSavedConfigUrl(), null);
  saveConfigUrl("https://example.com/p.json");
  assert.equal(loadSavedConfigUrl(), "https://example.com/p.json");
  clearConfigUrl();
  assert.equal(loadSavedConfigUrl(), null);
});

test("fetchCompanyProfile: rejects a non-https url before ever fetching", async () => {
  let called = false;
  const res = await fetchCompanyProfile("http://example.com/p.json", { fetchImpl: async () => { called = true; } });
  assert.equal(res.ok, false);
  assert.equal(called, false);
});

test("fetchCompanyProfile: valid JSON matching the schema succeeds", async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => GOLDEN });
  const res = await fetchCompanyProfile("https://example.com/p.json", { fetchImpl });
  assert.equal(res.ok, true);
  assert.deepEqual(res.data, GOLDEN);
});

test("fetchCompanyProfile: non-200 fails cleanly", async () => {
  const fetchImpl = async () => ({ ok: false, status: 404 });
  const res = await fetchCompanyProfile("https://example.com/p.json", { fetchImpl });
  assert.equal(res.ok, false);
  assert.match(res.error, /404/);
});

test("fetchCompanyProfile: non-JSON body fails cleanly", async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => { throw new SyntaxError("bad"); } });
  const res = await fetchCompanyProfile("https://example.com/p.json", { fetchImpl });
  assert.equal(res.ok, false);
});

test("fetchCompanyProfile: schema-invalid body (tampered fixture shape) fails cleanly", async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => ({ schema_version: 1, profile_name: "x", relay_url: "javascript:alert(1)", extra_field_not_allowed: true }) });
  const res = await fetchCompanyProfile("https://example.com/p.json", { fetchImpl });
  assert.equal(res.ok, false);
  assert.match(res.error, /^schema:/);
});

test("fetchCompanyProfile: network error / timeout is reported, not thrown", async () => {
  const fetchImpl = async () => { throw new Error("boom"); };
  const res = await fetchCompanyProfile("https://example.com/p.json", { fetchImpl });
  assert.equal(res.ok, false);
  assert.equal(res.error, "boom");
});

test("applyBranding: sets only well-formed --custom-property keys", () => {
  styleProps.clear();
  applyBranding({ "--accent": "#111", "not-a-custom-prop": "x", "--ok-2": "2px", "--Bad": "y" });
  assert.equal(styleProps.get("--accent"), "#111");
  assert.equal(styleProps.get("--ok-2"), "2px");
  assert.equal(styleProps.has("not-a-custom-prop"), false);
  assert.equal(styleProps.has("--Bad"), false);
});

test("applyBranding: no branding object is a no-op", () => {
  styleProps.clear();
  applyBranding(undefined);
  assert.equal(styleProps.size, 0);
});

test("getFeaturedTemplates / getPinnedKernelVersions read through a profile object", () => {
  assert.deepEqual(getFeaturedTemplates(GOLDEN), ["pillar-two-provision", "cbcr-notification"]);
  assert.deepEqual(getPinnedKernelVersions(GOLDEN), { "art-201": "1.4.0" });
  assert.equal(getFeaturedTemplates({}), null);
  assert.equal(getPinnedKernelVersions({}), null);
});

test("initCompanyProfile: no config= and no saved setting is a no-op", async () => {
  clearConfigUrl();
  const profile = await initCompanyProfile({ locationObj: { search: "" } });
  assert.equal(profile, null);
});

test("initCompanyProfile: valid ?config= applies branding, relay override, saves the URL, and exposes the active profile", async () => {
  clearConfigUrl();
  setRelayBaseOverride(null);
  styleProps.clear();
  const url = "https://example.com/p.json";
  globalThis.fetch = async () => ({ ok: true, json: async () => GOLDEN });
  const profile = await initCompanyProfile({ locationObj: { search: `?config=${encodeURIComponent(url)}` } });
  assert.deepEqual(profile, GOLDEN);
  assert.equal(loadSavedConfigUrl(), url);
  assert.equal(styleProps.get("--accent"), "#7a1fd9");
  assert.equal(currentRelayBase(), GOLDEN.relay_url);
  assert.deepEqual(getActiveCompanyProfile(), GOLDEN);
  setRelayBaseOverride(null);
});

test("initCompanyProfile: unreachable config falls back to defaults without throwing", async () => {
  clearConfigUrl();
  const url = "https://example.com/down.json";
  globalThis.fetch = async () => { throw new Error("ECONNREFUSED"); };
  const profile = await initCompanyProfile({ locationObj: { search: `?config=${encodeURIComponent(url)}` } });
  assert.equal(profile, null);
  // A failed fetch never persists the URL as the new saved setting.
  assert.equal(loadSavedConfigUrl(), null);
});
