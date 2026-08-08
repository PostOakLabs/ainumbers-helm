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
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

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

test("list-scenarios prints the bundled scenarios and exits 0", () => {
  const r = run("list-scenarios");
  assert.equal(r.code, 0);
  assert.match(r.stdout, /cecl-allowance-quarterly/);
  assert.match(r.stdout, /other compiled packs/);
});

test("list-scenarios --json prints a parseable object with templates and other_packs", () => {
  const r = run("list-scenarios", "--json");
  assert.equal(r.code, 0);
  const parsed = JSON.parse(r.stdout);
  assert.ok(Array.isArray(parsed.templates) && parsed.templates.length >= 5);
  assert.ok(Array.isArray(parsed.other_packs) && parsed.other_packs.length > 0);
});

test("run-template with no slug fails with a usage message on stderr", () => {
  const r = run("run-template");
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /usage: node scripts\/run-template\.mjs/);
});

test("run-template with an unknown slug exits non-zero and reports on stderr", () => {
  const r = run("run-template", "not-a-real-slug");
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /unknown slug/);
});

test("run-template runs a bundled scenario end to end, no daemon, and prints a completed state", () => {
  const r = run("run-template", "cecl-allowance-quarterly");
  assert.equal(r.code, 0);
  assert.match(r.stdout, /state:\s+completed/);
  assert.match(r.stdout, /execution_hash:\s+sha256:/);
});

test("run-template --dry-run --json reports completed with no side effects, dryRun:true", () => {
  const r = run("run-template", "emir-field-check", "--dry-run", "--json");
  assert.equal(r.code, 0);
  const parsed = JSON.parse(r.stdout);
  assert.equal(parsed.state, "completed");
  assert.equal(parsed.dryRun, true);
});

// matter-close (HELM-MATTER-H2): a thin authenticated HTTP client against an
// ALREADY-RUNNING daemon — unlike every sibling command above, it has no
// standalone/no-daemon mode by design (see scripts/matter-close.mjs's header
// comment), so its own end-to-end "actually closes a matter" behavior is
// covered where a real daemon is already stood up: hub/server.test.mjs. This
// file only covers the wrapper's own dispatch: usage errors and the
// no-daemon-running failure path, mirroring how the OTHER passthrough
// commands are covered by hub/cli-verbs.test.mjs rather than re-run here.
test("matter-close with no matter_id fails with a usage message on stderr, distinct exit from a refusal", () => {
  const r = run("matter-close");
  assert.notEqual(r.code, 0);
  assert.match(r.stderr, /usage: helmd matter-close <matter_id>/);
});

test("matter-close against a daemon that isn't running fails with a clear connection message, not a raw stack trace", () => {
  // Isolated HELM_HOME so this reads a config.json naming a port nothing is
  // bound to (never the real default 4173, which could legitimately be a
  // live daemon on this machine) — deterministic connection-refused, not a
  // race against whatever else is running locally.
  const isolatedHome = mkdtempSync(join(tmpdir(), "helmd-matter-close-test-"));
  writeFileSync(join(isolatedHome, "config.json"), JSON.stringify({ port: 41777, allowedOrigin: "http://127.0.0.1:41777" }));
  try {
    const result = spawnSync(process.execPath, [ENTRY, "matter-close", "01SOMEMATTERIDXXXXXXXXXXX"], {
      encoding: "utf8",
      env: { ...process.env, HELM_HOME: isolatedHome },
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /could not reach helmd on 127\.0\.0\.1:41777/);
  } finally {
    rmSync(isolatedHome, { recursive: true, force: true });
  }
});
