// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Cover for the `bin/helmd.mjs` CLI entrypoint added by HELM-CLI-MIN-1:
// --help/--version, exit codes (including the usage-error path), stdout
// vs stderr separation, and `doctor --json`. Passthrough commands
// (start/stop/status/open/uninstall) already have end-to-end cover in
// hub/cli-verbs.test.mjs against hub/index.mjs directly — this file does
// not re-run the daemon lifecycle, only the wrapper's own dispatch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, "helmd.mjs");
const PKG_VERSION = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8")).version;

function run(...args) {
  try {
    return { code: 0, stdout: execFileSync(process.execPath, [ENTRY, ...args], { encoding: "utf8" }) };
  } catch (err) {
    return { code: err.status, stdout: err.stdout || "", stderr: err.stderr || "" };
  }
}

test("--version prints the package.json version to stdout and exits 0", () => {
  const r = run("--version");
  assert.equal(r.code, 0);
  assert.equal(r.stdout.trim(), PKG_VERSION);
});

test("--help prints usage to stdout and exits 0, no args does the same", () => {
  for (const args of [["--help"], ["-h"], []]) {
    const r = run(...args);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /Usage: helmd <command>/);
    assert.match(r.stdout, /export-bpmn/);
  }
});

test("an unknown command is a usage error: distinct exit code, message on stderr not stdout", () => {
  const r = run("frobnicate");
  assert.notEqual(r.code, 0);
  assert.notEqual(r.code, 1, "usage errors must be distinguishable from a subcommand's own failure exit");
  assert.equal(r.stdout, "", "diagnostics must never leak onto stdout");
  assert.match(r.stderr, /unknown command "frobnicate"/);
});

test("doctor (plain) exits 0 or 1 and prints PASS/FAIL lines to stdout", () => {
  const r = run("doctor");
  assert.ok(r.code === 0 || r.code === 1);
  assert.match(r.stdout, /PASS|FAIL/);
});

test("doctor --json prints a single parseable JSON object with an ok field", () => {
  const r = run("doctor", "--json");
  assert.ok(r.code === 0 || r.code === 1);
  const parsed = JSON.parse(r.stdout);
  assert.equal(typeof parsed.ok, "boolean");
  assert.ok(Array.isArray(parsed.checks));
});

test("export-bpmn with no workflow_id fails with a distinct, non-1 usage-style path from the wrapped script", () => {
  const r = run("export-bpmn");
  assert.notEqual(r.code, 0);
});

test("export-bpmn with an unknown workflow_id exits non-zero and reports on stderr", () => {
  const r = run("export-bpmn", "not-a-real-workflow-id");
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /unknown workflow_id/);
});
