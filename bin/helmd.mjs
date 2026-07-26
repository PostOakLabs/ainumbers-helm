#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-CLI-MIN-1: `bin` entrypoint exposing what helmd already does as an
// installable command, plus `export-bpmn`. A thin wrapper only — it never
// duplicates hub/index.mjs's daemon-lifecycle logic and never edits that
// file (HELM-ANCHOR-WIRE-1 was concurrently writing it; editing it here
// would have collided). start/stop/status/open/uninstall are forwarded to
// hub/index.mjs as a subprocess, argv and exit code passed through
// unchanged. `doctor` is the one exception: it calls hub/doctor.mjs's
// runDoctor() directly (a plain function, not the CLI shell) so this file
// can offer --json without touching hub/index.mjs at all.
//
// Conventions followed: clig.dev (Command Line Interface Guidelines) —
// --help/--version, stdout for data, stderr for diagnostics, a usage error
// (unknown command) gets its own exit code distinct from a subcommand's own
// failure exit. NO_COLOR: this CLI never emits color codes, so NO_COLOR is
// honoured trivially by construction. No CLI framework (commander/yargs/
// oclif/meow) — flag parsing here is a handful of string checks; anything
// past --help/--version/--json is forwarded to the wrapped script verbatim.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PKG = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

const HELMD_ENTRY = join(ROOT, "hub", "index.mjs");
const EXPORT_BPMN_ENTRY = join(ROOT, "scripts", "export-bpmn.mjs");

// Read straight off hub/index.mjs's own dispatch, not a hand-copied guess —
// see the row's warning: "read the dispatcher, do not grep a guessed list."
const PASSTHROUGH_COMMANDS = new Set(["start", "stop", "status", "open", "uninstall"]);

function printHelp() {
  console.log(`helmd — local-first control plane CLI

Usage: helmd <command> [options]

Commands:
  start [--open]      start the helmd hub daemon (--open also opens the pairing URL)
  stop                stop a running helmd daemon
  status              report whether helmd is running
  doctor [--json]     run local self-checks (config, token, state dir, port)
  open                open the pairing URL in the default browser
  uninstall           remove the autostart entry / shortcut
  export-bpmn <workflow_id> [out.bpmn]
                      export a compiled pack's workflow as BPMN 2.0 XML

Options:
  -h, --help          show this help and exit 0
  -v, --version       print the version and exit 0

Exit codes: 0 success; a subcommand's own failure exit is passed through
unchanged; an unknown command is a usage error and exits 2.

Stability: start/stop/status/doctor/open/uninstall/export-bpmn and their
plain-text output/exit codes are STABLE. --json output shapes are
PROVISIONAL and may change without notice until this line is removed.`);
}

function printVersion() {
  console.log(PKG.version);
}

const argv = process.argv.slice(2);
const [cmd, ...rest] = argv;

if (cmd === undefined || cmd === "-h" || cmd === "--help") {
  printHelp();
  process.exit(0);
}

if (cmd === "-v" || cmd === "--version") {
  printVersion();
  process.exit(0);
}

if (PASSTHROUGH_COMMANDS.has(cmd)) {
  const result = spawnSync(process.execPath, [HELMD_ENTRY, cmd, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "doctor") {
  const { runDoctor } = await import(pathToFileURL(join(ROOT, "hub", "doctor.mjs")));
  const report = await runDoctor();
  if (rest.includes("--json")) {
    console.log(JSON.stringify(report));
  } else {
    for (const c of report.checks) {
      console.log(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail !== undefined ? `  (${c.detail})` : ""}`);
    }
  }
  // Not process.exit(): one of runDoctor's checks (version_check_notice) can
  // leave an async handle mid-teardown, and a forced exit racing that
  // teardown crashes libuv on Windows (`UV_HANDLE_CLOSING` assertion, node
  // v24) — reproduces identically via `node hub/index.mjs doctor`, so it
  // predates this file. Setting exitCode and letting the loop drain avoids
  // racing the handle close without touching hub/doctor.mjs.
  process.exitCode = report.ok ? 0 : 1;
} else if (cmd === "export-bpmn") {
  const result = spawnSync(process.execPath, [EXPORT_BPMN_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else {
  console.error(`helmd: unknown command "${cmd}" (expected: start | stop | status | doctor | open | uninstall | export-bpmn)`);
  console.error("Run 'helmd --help' for usage.");
  process.exit(2);
}
