// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-CHECK-BATCH-1 — RED-BEFORE-GREEN for §2.3 (anchor-burst), §2.4
// (continue-and-summarize), §2.5 (path traversal), plus a regression test
// proving the single-file path is byte-for-byte unchanged
// (HELM-VERIFY-CLI-BUILD-SPEC.md §2). Uses the REAL vendored
// art-508-recompute-bordereau kernel via the REAL compiled pack — same
// fixtures hub/check.test.mjs already exercises, no mock kernel.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { EXIT } from "../hub/check.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CHECK_ENTRY = join(HERE, "check.mjs");
const PRELOAD = join(HERE, "verify-network-guard-preload.cjs");
const PACK_ID = "pack-art-508-recompute-bordereau";

const FIXTURES = JSON.parse(
  readFileSync(join(HERE, "..", "hub", "vendored", "ocg", "kernels", "fixtures", "art-508-recompute-bordereau.fixtures.json"), "utf8")
);

function vector(name) {
  const v = FIXTURES.vectors.find((v) => v.name === name);
  assert.ok(v, `fixture vector "${name}" not found`);
  return v;
}

function inputBodyFor(vectorName) {
  const pp = { ...vector(vectorName).policy_parameters };
  const asserted = pp.asserted_totals;
  delete pp.asserted_totals;
  const body = { inputs: pp };
  if (asserted !== undefined) body.asserted = asserted;
  return JSON.stringify(body);
}

function workDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function helmHomeEnv() {
  return { HELM_HOME: mkdtempSync(join(tmpdir(), "helm-check-batch-home-")) };
}

function runCli(args, { cwd } = {}) {
  return spawnSync(process.execPath, [CHECK_ENTRY, ...args], {
    encoding: "utf8",
    cwd: cwd ?? process.cwd(),
    env: { ...process.env, ...helmHomeEnv() },
  });
}

function runCliUnderPreload(args, { cwd } = {}) {
  return spawnSync(process.execPath, ["--require", PRELOAD, CHECK_ENTRY, ...args], {
    encoding: "utf8",
    cwd: cwd ?? process.cwd(),
    env: { ...process.env, ...helmHomeEnv() },
  });
}

// --- regression: single-file path is unchanged ------------------------------

test("regression: single positional file behaves exactly as before (unbatched path untouched)", () => {
  const dir = workDir("helm-check-batch-regression-");
  const inputPath = join(dir, "in.json");
  writeFileSync(inputPath, inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  const result = runCli([PACK_ID, inputPath, "--no-anchor", "--json"], { cwd: dir });
  assert.equal(result.status, EXIT.MATCH, result.stderr);
  const out = JSON.parse(result.stdout);
  assert.equal(out.result, "match");
  assert.ok(existsSync(join(dir, "in.json.check.json")));
});

test("regression: single-file usage error (missing input_file) is unchanged", () => {
  const result = runCli([PACK_ID]);
  assert.equal(result.status, EXIT.USAGE_ERROR);
});

// --- §2.3 anchor-burst: batch must default --no-anchor, never N calls ------

test("canary: the network-blocking preload actually traps a call (proves the harness isn't vacuous)", () => {
  const result = spawnSync(
    process.execPath,
    ["--require", PRELOAD, "-e", "try { fetch('http://example.invalid'); process.exit(9); } catch (e) { process.exit(e.message.includes('NETWORK_BLOCKED') ? 1 : 8); }"],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 1, `expected the canary fetch to trip NETWORK_BLOCKED, got status=${result.status} stderr=${result.stderr}`);
});

test("RED: single-file check WITHOUT --no-anchor attempts a network call — what a naive per-file batch loop would multiply by N", () => {
  const dir = workDir("helm-check-batch-red-");
  const inputPath = join(dir, "a.json");
  writeFileSync(inputPath, inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  const result = runCliUnderPreload([PACK_ID, inputPath], { cwd: dir });
  assert.match(result.stdout, /NETWORK_BLOCKED/, `expected the default (non---no-anchor) single-file path to attempt an anchor call; stdout=${result.stdout}`);
});

test("GREEN: batch mode over 3 files with NO flags attempts ZERO network calls under the same preload", () => {
  const dir = workDir("helm-check-batch-green-");
  writeFileSync(join(dir, "a.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "b.json"), inputBodyFor("totals-differ-reported-as-a-finding"));
  writeFileSync(join(dir, "c.json"), inputBodyFor("recompute-only-is-its-own-state"));
  const result = runCliUnderPreload([PACK_ID, "a.json", "b.json", "c.json"], { cwd: dir });
  assert.doesNotMatch(result.stdout, /NETWORK_BLOCKED/, `batch attempted a network call: stdout=${result.stdout}`);
  assert.doesNotMatch(result.stderr, /NETWORK_BLOCKED/, `batch attempted a network call: stderr=${result.stderr}`);
  assert.equal(result.status, 0, result.stderr);
});

test("GREEN: --glob batch also attempts ZERO network calls, --no-anchor accepted as a no-op affirmation", () => {
  const dir = workDir("helm-check-batch-green-glob-");
  writeFileSync(join(dir, "a.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "b.json"), inputBodyFor("totals-differ-reported-as-a-finding"));
  const result = runCliUnderPreload([PACK_ID, "--glob", "*.json", "--no-anchor"], { cwd: dir });
  assert.doesNotMatch(result.stdout, /NETWORK_BLOCKED/, `batch attempted a network call: stdout=${result.stdout}`);
  assert.equal(result.status, 0, result.stderr);
});

// --- §2.4 continue-and-summarize --------------------------------------------

test("§2.4: one bad file among three does not abort the batch, is named in the summary, exit is nonzero", () => {
  const dir = workDir("helm-check-batch-summarize-");
  writeFileSync(join(dir, "good.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "diff.json"), inputBodyFor("totals-differ-reported-as-a-finding"));
  writeFileSync(join(dir, "bad.json"), "{ not valid json");
  const result = runCli([PACK_ID, "good.json", "bad.json", "diff.json"], { cwd: dir });
  assert.notEqual(result.status, 0, "batch with one failure must exit nonzero even though 2 of 3 succeeded");
  assert.match(result.stdout, /FAILED\s+bad\.json/, `summary must name the failed file by path: ${result.stdout}`);
  assert.match(result.stdout, /MATCH\s+good\.json/);
  assert.match(result.stdout, /DIFFERS\s+diff\.json/);
  assert.ok(existsSync(join(dir, "good.json.check.json")), "a good file's bundle must still be written despite another file's failure");
  assert.ok(existsSync(join(dir, "diff.json.check.json")), "a differing (not failed) file's bundle must still be written");
});

test("§2.4: --json batch summary names failures machine-readably", () => {
  const dir = workDir("helm-check-batch-summarize-json-");
  writeFileSync(join(dir, "good.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "bad.json"), "{ not valid json");
  const result = runCli([PACK_ID, "good.json", "bad.json", "--json"], { cwd: dir });
  assert.notEqual(result.status, 0);
  const out = JSON.parse(result.stdout);
  assert.equal(out.summary.total, 2);
  assert.equal(out.summary.failed, 1);
  const badEntry = out.files.find((f) => f.file === "bad.json");
  assert.equal(badEntry.ran, false);
});

test("all-success batch exits 0", () => {
  const dir = workDir("helm-check-batch-allgood-");
  writeFileSync(join(dir, "a.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "b.json"), inputBodyFor("totals-differ-reported-as-a-finding"));
  const result = runCli([PACK_ID, "a.json", "b.json"], { cwd: dir });
  assert.equal(result.status, 0, result.stderr);
});

// --- §2.5 path traversal -----------------------------------------------------

test("§2.5: --out-dir escaping cwd is rejected before any write", () => {
  const dir = workDir("helm-check-batch-traversal-outdir-");
  writeFileSync(join(dir, "a.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "b.json"), inputBodyFor("totals-differ-reported-as-a-finding"));
  const result = runCli([PACK_ID, "a.json", "b.json", "--out-dir", "../../../etc"], { cwd: dir });
  assert.equal(result.status, EXIT.USAGE_ERROR);
  assert.match(result.stderr, /escapes the working directory/);
  assert.ok(!existsSync(join(dir, "a.json.check.json")), "no bundle should have been written before the traversal was rejected");
});

test("§2.5: a --glob pattern reaching outside cwd is rejected before any read", () => {
  const parent = workDir("helm-check-batch-traversal-glob-parent-");
  writeFileSync(join(parent, "secret.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  const child = join(parent, "child");
  mkdirSync(child);
  const result = runCli([PACK_ID, "--glob", "../secret.json"], { cwd: child });
  assert.equal(result.status, EXIT.USAGE_ERROR);
  assert.match(result.stderr, /escapes the working directory/);
  assert.ok(!existsSync(join(child, "secret.json.check.json")));
  assert.ok(!existsSync(join(parent, "secret.json.check.json")));
});

test("--out-dir within cwd, and --glob within cwd, both work normally in batch mode", () => {
  const dir = workDir("helm-check-batch-outdir-ok-");
  mkdirSync(join(dir, "out"));
  writeFileSync(join(dir, "a.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  writeFileSync(join(dir, "b.json"), inputBodyFor("totals-differ-reported-as-a-finding"));
  const result = runCli([PACK_ID, "--glob", "*.json", "--out-dir", "out"], { cwd: dir });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(existsSync(join(dir, "out", "a.json.check.json")));
  assert.ok(existsSync(join(dir, "out", "b.json.check.json")));
});

test("usage error: passing both --glob and positional files in batch mode is rejected", () => {
  const dir = workDir("helm-check-batch-bothargs-");
  writeFileSync(join(dir, "a.json"), inputBodyFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns"));
  const result = runCli([PACK_ID, "a.json", "--glob", "*.json"], { cwd: dir });
  assert.equal(result.status, EXIT.USAGE_ERROR);
});

test("usage error: --glob matching nothing is a usage error, not a silent no-op success", () => {
  const dir = workDir("helm-check-batch-noglobmatch-");
  const result = runCli([PACK_ID, "--glob", "*.nope"], { cwd: dir });
  assert.equal(result.status, EXIT.USAGE_ERROR);
});
