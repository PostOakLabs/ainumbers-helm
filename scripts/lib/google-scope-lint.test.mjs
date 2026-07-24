// Fixture strings here necessarily NAME the forbidden scopes (that's what
// makes them useful test data) — google-scope-lint.mjs excludes this file's
// own basename from scanRepoForForbiddenGoogleScopes's real repo walk so
// this file never trips the rule it's testing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  isForbiddenGoogleScope,
  findForbiddenScopes,
  extractScopeArraysFromSource,
  scanRepoForForbiddenGoogleScopes,
} from "./google-scope-lint.mjs";

test("isForbiddenGoogleScope: exact-match only, drive.file is never caught", () => {
  assert.equal(isForbiddenGoogleScope("drive.readonly"), true);
  assert.equal(isForbiddenGoogleScope("drive"), true);
  assert.equal(isForbiddenGoogleScope("https://www.googleapis.com/auth/drive.readonly"), true);
  assert.equal(isForbiddenGoogleScope("https://www.googleapis.com/auth/drive"), true);
  assert.equal(isForbiddenGoogleScope("drive.file"), false);
  assert.equal(isForbiddenGoogleScope("https://www.googleapis.com/auth/drive.file"), false);
  assert.equal(isForbiddenGoogleScope("Files.Read"), false);
});

test("findForbiddenScopes: filters a mixed scope array", () => {
  assert.deepEqual(findForbiddenScopes(["openid", "drive.file", "drive.readonly"]), ["drive.readonly"]);
  assert.deepEqual(findForbiddenScopes(["drive.file"]), []);
  assert.deepEqual(findForbiddenScopes(undefined), []);
});

test("extractScopeArraysFromSource: pulls scopes/defaultScopes array literals", () => {
  const src = `export const X = { defaultScopes: ["openid", "drive.file"] };\nconst y = { scopes: ["drive.readonly"] };`;
  assert.deepEqual(extractScopeArraysFromSource(src), [
    ["openid", "drive.file"],
    ["drive.readonly"],
  ]);
});

test("scanRepoForForbiddenGoogleScopes: catches a violation in a fixture tree, clean tree reports nothing", () => {
  const dirty = mkdtempSync(join(tmpdir(), "helm-scopelint-dirty-"));
  writeFileSync(join(dirty, "contract.json"), JSON.stringify({ scopes: ["drive.readonly"] }));
  writeFileSync(join(dirty, "provider.mjs"), `export const P = { defaultScopes: ["drive.file"] };\n`);
  const dirtyViolations = scanRepoForForbiddenGoogleScopes(dirty);
  assert.equal(dirtyViolations.length, 1);
  assert.equal(dirtyViolations[0].scope, "drive.readonly");
  rmSync(dirty, { recursive: true, force: true });

  const clean = mkdtempSync(join(tmpdir(), "helm-scopelint-clean-"));
  mkdirSync(join(clean, "sub"));
  writeFileSync(join(clean, "sub", "contract.json"), JSON.stringify({ scopes: ["drive.file"] }));
  assert.deepEqual(scanRepoForForbiddenGoogleScopes(clean), []);
  rmSync(clean, { recursive: true, force: true });
});

test("scanRepoForForbiddenGoogleScopes: this repo (hub/ui/schema) is clean", () => {
  const ROOT = join(new URL(".", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"), "..", "..");
  const violations = scanRepoForForbiddenGoogleScopes(ROOT);
  assert.deepEqual(violations, [], `expected no forbidden Google scopes in the repo, found: ${JSON.stringify(violations)}`);
});
