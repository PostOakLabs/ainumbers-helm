import test from "node:test";
import assert from "node:assert/strict";
import { parseTokenFromHash, isCacheStale } from "./api.mjs";

test("parseTokenFromHash reads #token= fragment", () => {
  assert.equal(parseTokenFromHash("#token=abc123"), "abc123");
});

test("parseTokenFromHash decodes percent-encoding", () => {
  assert.equal(parseTokenFromHash("#token=a%2Fb"), "a/b");
});

test("parseTokenFromHash returns null when absent", () => {
  assert.equal(parseTokenFromHash(""), null);
  assert.equal(parseTokenFromHash("#other=1"), null);
});

test("parseTokenFromHash finds token among other fragment params", () => {
  assert.equal(parseTokenFromHash("#foo=1&token=xyz&bar=2"), "xyz");
});

test("isCacheStale: fresh timestamp is not stale", () => {
  assert.equal(isCacheStale(new Date().toISOString(), 60_000), false);
});

test("isCacheStale: old timestamp is stale", () => {
  const old = new Date(Date.now() - 120_000).toISOString();
  assert.equal(isCacheStale(old, 60_000), true);
});

test("isCacheStale: unparseable timestamp is stale", () => {
  assert.equal(isCacheStale("not-a-date", 60_000), true);
});
