import { test } from "node:test";
import assert from "node:assert/strict";
import { compareVersions, checkVersion } from "./version-check.mjs";

test("compareVersions: orders major/minor/patch", () => {
  assert.equal(compareVersions("0.1.0", "0.2.0"), -1);
  assert.equal(compareVersions("1.0.0", "0.9.9"), 1);
  assert.equal(compareVersions("0.1.0", "0.1.0"), 0);
  assert.equal(compareVersions("0.1.2", "0.1.10"), -1);
});

function fakeFetch(body, { ok = true, status = 200 } = {}) {
  return async () => ({ ok, status, json: async () => body });
}

test("checkVersion: up to date when current >= latest", async () => {
  const result = await checkVersion({
    currentVersion: "0.2.0",
    fetchImpl: fakeFetch({
      latest_version: "0.2.0",
      minimum_supported_version: "0.1.0",
      release_url: "https://github.com/PostOakLabs/ainumbers-helm/releases/tag/v0.2.0",
      published_at: "2026-08-01T00:00:00Z",
    }),
  });
  assert.equal(result.checked, true);
  assert.equal(result.upToDate, true);
  assert.equal(result.belowMinimumSupported, false);
});

test("checkVersion: flags an available update", async () => {
  const result = await checkVersion({
    currentVersion: "0.1.0",
    fetchImpl: fakeFetch({
      latest_version: "0.2.0",
      minimum_supported_version: "0.1.0",
      release_url: "https://github.com/PostOakLabs/ainumbers-helm/releases/tag/v0.2.0",
      published_at: "2026-08-01T00:00:00Z",
    }),
  });
  assert.equal(result.checked, true);
  assert.equal(result.upToDate, false);
});

test("checkVersion: network failure degrades to unchecked, not an error", async () => {
  const result = await checkVersion({
    currentVersion: "0.1.0",
    fetchImpl: async () => { throw new Error("ECONNREFUSED"); },
  });
  assert.equal(result.checked, false);
  assert.match(result.reason, /unreachable/);
});

test("checkVersion: malformed response fails schema validation, not a throw", async () => {
  const result = await checkVersion({
    currentVersion: "0.1.0",
    fetchImpl: fakeFetch({ latest_version: "not-a-semver" }),
  });
  assert.equal(result.checked, false);
  assert.equal(result.reason, "response failed schema validation");
});

test("checkVersion: non-200 response degrades to unchecked", async () => {
  const result = await checkVersion({
    currentVersion: "0.1.0",
    fetchImpl: fakeFetch({}, { ok: false, status: 404 }),
  });
  assert.equal(result.checked, false);
  assert.equal(result.reason, "http 404");
});
