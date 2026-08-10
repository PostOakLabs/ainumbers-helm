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
const LIST_SCENARIOS_ENTRY = join(ROOT, "scripts", "list-scenarios.mjs");
const RUN_TEMPLATE_ENTRY = join(ROOT, "scripts", "run-template.mjs");
const CHECK_ENTRY = join(ROOT, "scripts", "check.mjs");
const VERIFY_ENTRY = join(ROOT, "scripts", "verify.mjs");
const MATTER_CLOSE_ENTRY = join(ROOT, "scripts", "matter-close.mjs");
const BILAT_PUBKEY_ENTRY = join(ROOT, "scripts", "bilat-pubkey.mjs");
const BILAT_EXPORT_ENTRY = join(ROOT, "scripts", "bilat-export.mjs");
const BILAT_IMPORT_ENTRY = join(ROOT, "scripts", "bilat-import.mjs");

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
  list-scenarios [--json]
                      list bundled sample-data scenarios (and other compiled packs)
  run-template <slug> [--dry-run] [--json]
                      run a bundled scenario end to end using its sample data, no daemon required
  check <pack_id> <input_file> [--out <bundle.json>] [--no-anchor] [--json]
                      recompute a pack's kernel against a reviewer's own extract and diff
                      it against an asserted value — no daemon, no upload. Exit codes: 0
                      match, 1 differs, 2 no asserted value (recompute-only), 3 insufficient
                      input, 4 usage error, 5 scope disagreement.
  check <pack_id> --glob "<pattern>" [--out-dir <dir>] [--no-anchor] [--json]
  check <pack_id> <file1> <file2> ... [--out-dir <dir>] [--no-anchor] [--json]
                      batch mode (triggered by --glob or more than one input file): runs
                      each file through the same check unattended, never anchors per file
                      regardless of --no-anchor/--anchor state, continues past a per-file
                      failure and names every failure in the summary, and exits nonzero if
                      ANY file failed to run (0 if every file ran, whatever its comparison
                      result). --out-dir and --glob matches are rejected if they resolve
                      outside the current working directory.
  verify <bundle.json> --keys <publicKeys.json> [--json] [--anchor-full]
                      verify an evidence bundle offline against a caller-supplied public-key
                      file — no daemon, no network. Exit codes: 0 valid, 1 invalid, 2 usage
                      error (verification never attempted).
  matter-close <matter_id> [--out <export.json>] [--json]
                      close a matter and trigger its signed closeout export — requires
                      helmd to be running (this is a thin authenticated client of the
                      already-running daemon, not a standalone command). Exists so an
                      external tool's own closeout event (e.g. a git post-commit hook) can
                      call Helm's export without touching helmd's HTTP API directly.
  bilat-pubkey [--json]
                      print this Helm's own public keys in the shareable format a
                      counterparty needs for bilat-import --peer-keys. No daemon required.
  bilat-export --org-id <id> --payload-type <type> --payload-file <payload.json>
               --out <envelope.json> [--json]
                      wrap an already-produced local artifact (matter bundle / BILAT-CSR
                      receipt / BILAT-COSIGN head) in a signed Helm-to-Helm exchange
                      envelope, written to a file. File/bundle exchange only — no listener,
                      no network call, no daemon required (BILAT-H2H-BUILD-SPEC.md §2).
  bilat-import <envelope.json> --peer-keys <peerPublicKeys.json> [--out <payload.json>]
               [--strict] [--json]
                      verify a received envelope against a counterparty's public keys and,
                      on success, write the recovered payload. Fails closed (exit 1) on bad
                      signature, unrecognized version, or unrecognized payload_type — never
                      a partial write. No daemon required.

Options:
  -h, --help          show this help and exit 0
  -v, --version       print the version and exit 0

Exit codes: 0 success; a subcommand's own failure exit is passed through
unchanged (check has its own six-way exit contract, see above); an unknown
command is a usage error and exits 2.

Stability: start/stop/status/doctor/open/uninstall/export-bpmn/list-scenarios/
run-template/check/verify/matter-close/bilat-pubkey/bilat-export/bilat-import
and their plain-text output/exit codes are STABLE. --json output shapes are
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
} else if (cmd === "list-scenarios") {
  const result = spawnSync(process.execPath, [LIST_SCENARIOS_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "run-template") {
  const result = spawnSync(process.execPath, [RUN_TEMPLATE_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "check") {
  const result = spawnSync(process.execPath, [CHECK_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "verify") {
  const result = spawnSync(process.execPath, [VERIFY_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "matter-close") {
  const result = spawnSync(process.execPath, [MATTER_CLOSE_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "bilat-pubkey") {
  const result = spawnSync(process.execPath, [BILAT_PUBKEY_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "bilat-export") {
  const result = spawnSync(process.execPath, [BILAT_EXPORT_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else if (cmd === "bilat-import") {
  const result = spawnSync(process.execPath, [BILAT_IMPORT_ENTRY, ...rest], { stdio: "inherit" });
  process.exit(result.status ?? 1);
} else {
  console.error(`helmd: unknown command "${cmd}" (expected: start | stop | status | doctor | open | uninstall | export-bpmn | list-scenarios | run-template | check | verify | matter-close | bilat-pubkey | bilat-export | bilat-import)`);
  console.error("Run 'helmd --help' for usage.");
  process.exit(2);
}
