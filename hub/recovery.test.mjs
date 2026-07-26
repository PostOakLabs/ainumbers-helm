// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-JOURNAL-REPAIR-1: a broken journal.db used to be a dead end —
// `process.exit(1)` with no recovery path (HELM-TECHNICAL-ISSUES-2026-07-24
// §1, reproduced for real on Tim's machine 2026-07-25). This covers the
// quarantine primitive in isolation and, end-to-end, that a daemon booted
// against a genuinely corrupted journal (a mid-stream digest mismatch, not a
// missing file — mirroring the real repro's torn write) quarantines the old
// state and reaches a real listening state on the fresh one, not just that
// `verified.ok` flips.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";
import { quarantineStateDir } from "./recovery.mjs";
import { openJournal, appendEntry, replayVerify, streamHeads } from "./journal.mjs";

// ---- unit: quarantineStateDir -------------------------------------------

function unitFixture() {
  const dir = mkdtempSync(join(tmpdir(), "helm-recovery-unit-"));
  writeFileSync(join(dir, "config.json"), JSON.stringify({ port: 4173, idleTimeoutMs: 999 }));
  writeFileSync(join(dir, "journal.db"), "not really sqlite, stands in for a torn file");
  writeFileSync(join(dir, "keys.enc.json"), "stand-in identity material");
  return dir;
}

test("quarantineStateDir: renames the broken dir aside, never deletes it", () => {
  const dir = unitFixture();
  let quarantinePath;
  try {
    ({ quarantinePath } = quarantineStateDir(dir, { seq: 3, streamId: "run-1" }));
    assert.ok(quarantinePath.includes(".broken-"));
    assert.equal(existsSync(dir), true, "a fresh dir exists at the original path");
    assert.equal(existsSync(join(quarantinePath, "journal.db")), true, "the broken journal was moved, not deleted");
    assert.equal(existsSync(join(quarantinePath, "keys.enc.json")), true, "old identity material was moved, not deleted");
    assert.equal(existsSync(join(dir, "journal.db")), false, "the fresh dir starts with no journal — re-init, not repair");
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (quarantinePath) rmSync(quarantinePath, { recursive: true, force: true });
  }
});

test("quarantineStateDir: writes a crash-log with the original failure detail into the quarantined copy", () => {
  const dir = unitFixture();
  let quarantinePath;
  try {
    const brokenAt = { seq: 3, streamId: "run-1", expected: "aa", found: "bb" };
    ({ quarantinePath } = quarantineStateDir(dir, brokenAt));
    const crashLogPath = join(quarantinePath, "crash-log.json");
    const log = JSON.parse(readFileSync(crashLogPath, "utf8"));
    assert.deepEqual(log.brokenAt, brokenAt);
    assert.equal(log.originalPath, dir);
    assert.match(log.reason, /journal replay integrity check failed/);
    assert.ok(log.quarantinedAt);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (quarantinePath) rmSync(quarantinePath, { recursive: true, force: true });
  }
});

test("quarantineStateDir: carries config.json forward — a torn journal write says nothing about the user's port/timeout prefs", () => {
  const dir = unitFixture();
  let quarantinePath;
  try {
    ({ quarantinePath } = quarantineStateDir(dir, { seq: 1 }));
    const config = JSON.parse(readFileSync(join(dir, "config.json"), "utf8"));
    assert.equal(config.port, 4173);
    assert.equal(config.idleTimeoutMs, 999);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (quarantinePath) rmSync(quarantinePath, { recursive: true, force: true });
  }
});

test("quarantineStateDir: is a no-op on config.json when the broken dir never had one", () => {
  const dir = mkdtempSync(join(tmpdir(), "helm-recovery-unit-noconfig-"));
  writeFileSync(join(dir, "journal.db"), "torn");
  let quarantinePath;
  try {
    ({ quarantinePath } = quarantineStateDir(dir, { seq: 1 }));
    assert.equal(existsSync(join(dir, "config.json")), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (quarantinePath) rmSync(quarantinePath, { recursive: true, force: true });
  }
});

// ---- end-to-end: helmd start against a genuinely corrupted journal ------
//
// Same safety properties cli-verbs.test.mjs depends on: HELM_HOME is a
// unique temp dir and the port is unique, so this can never reach a real
// helmd. HELM_NO_OPEN also gates the isFirstRun autostart/shortcut install
// (see index.mjs) — the recovery boot re-enters first-run (the quarantined
// dir's token is gone), so without that gate this test would write a real
// registry/LaunchAgent entry on the machine running the suite.

const TMP = mkdtempSync(join(tmpdir(), "helm-recovery-e2e-"));
const PORT = 41779;
const ORIGIN = `http://127.0.0.1:${PORT}`;
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "", idleTimeoutMs: 999999 }));

process.env.HELM_HOME = TMP;
const { loadOrCreateToken } = await import("./token.mjs");
const { loadOrCreateKeys } = await import("./keys.mjs");
// Mirrors the real repro: prior runs got far enough to mint a token/keys
// (this daemon has "started" before, per HELM-TECHNICAL-ISSUES-2026-07-24
// §1's three prior download/run attempts) before a later run tore the
// journal mid-write.
loadOrCreateToken();
loadOrCreateKeys();

const BROKEN_SEQ = 1;
{
  const db = openJournal(join(TMP, "journal.db"));
  const entry = {
    period_start: "2026-07-23T00:00:00.000Z",
    period_end: "2026-07-23T00:00:01.000Z",
    reference_db_version: "kernels@2026-07-23",
    triggering_input_digest: "sha256:" + "b".repeat(64),
    humans_involved: [],
  };
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: { ...entry, state: "queued" } });
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: { ...entry, state: "running" } });
  // Torn-write style corruption: flip a stored entry_digest so the running
  // hash at that seq no longer recomputes — same mechanism as the negative
  // fixture in journal.test.mjs, at a MID-stream seq per the row's ask
  // ("mirror the repro: a torn write, not a missing file").
  db.prepare("UPDATE journal SET entry_digest = ? WHERE seq = ?").run("f".repeat(64), BROKEN_SEQ);
  // Confirm this fixture is actually broken before handing it to the daemon —
  // RETRO-ORCH-2026-07-25 §4: show the failure red before trusting the fix green.
  const preCheck = replayVerify(db);
  assert.equal(preCheck.ok, false, "fixture setup sanity: the journal must be genuinely corrupted");
  assert.equal(preCheck.brokenAt.seq, BROKEN_SEQ);
  db.close();
}

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
const ENV = { ...process.env, HELM_HOME: TMP, HELM_NO_OPEN: "1" };

let daemon;
let quarantinePathToClean = null;
after(() => {
  if (daemon && daemon.exitCode === null) daemon.kill();
  rmSync(TMP, { recursive: true, force: true });
  if (quarantinePathToClean) rmSync(quarantinePathToClean, { recursive: true, force: true });
});

function helmd(...args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [ENTRY, ...args], { env: ENV, encoding: "utf8" }) };
  } catch (err) {
    return { code: err.status, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

// Waits for `marker`, not just "Helm is running." — the recovery banner
// prints AFTER that line (same order as the ordinary autostart/shortcut
// announcements it's modeled on), so resolving on "Helm is running." alone
// raced the stdout chunk carrying it and read as missing on a fast machine.
// "cli channel listening" is the last line every boot ever prints, so
// waiting for it guarantees everything above (recovery banner included) has
// already been flushed to the accumulated buffer.
function waitForRunning(child, marker = "cli channel listening") {
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`daemon did not report ready:\n${out}`)), 20000);
    child.stdout.on("data", (c) => {
      out += c.toString("utf8");
      if (out.includes(marker)) {
        clearTimeout(timer);
        resolve(out);
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`daemon exited early with ${code}:\n${out}`));
    });
  });
}

test("start against a genuinely corrupted journal: quarantines (renames, never deletes), re-inits fresh, and actually reaches a listening state", async () => {
  daemon = spawn(process.execPath, [ENTRY, "start"], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  const startupOutput = await waitForRunning(daemon);
  assert.match(startupOutput, /Helm is running\./);

  // Visible from a double-click, not just a terminal (row buildable #2):
  // the quarantine + crash-log location are announced in the same banner
  // the "Helm is running." check above just proved was printed.
  assert.match(startupOutput, /corrupted journal was found and quarantined/);
  assert.match(startupOutput, /quarantined state:/);
  assert.match(startupOutput, /failure details:/);

  const quarantineMatch = startupOutput.match(/quarantined state:\s*(\S+)/);
  const crashLogMatch = startupOutput.match(/failure details:\s*(\S+)/);
  assert.ok(quarantineMatch, "quarantine path printed");
  assert.ok(crashLogMatch, "crash-log path printed");
  const quarantinePath = quarantineMatch[1];
  const crashLogPath = crashLogMatch[1];
  quarantinePathToClean = quarantinePath;

  assert.ok(existsSync(quarantinePath), "quarantined dir exists on disk");
  assert.notEqual(quarantinePath, TMP, "quarantine target is a sibling, not the live state dir");
  const crashLog = JSON.parse(readFileSync(crashLogPath, "utf8"));
  assert.equal(crashLog.brokenAt.seq, BROKEN_SEQ);

  // The daemon really is up, not just past the verify check: status over the
  // CLI channel, on the configured port, same as a healthy boot.
  const status = helmd("status");
  assert.equal(status.code, 0, status.out);
  assert.match(status.out, new RegExp(`port\\s+${PORT}`));

  // config.json (user preference, unrelated to the torn journal) survived
  // the quarantine instead of silently reverting to daemon defaults.
  const liveConfig = JSON.parse(readFileSync(join(TMP, "config.json"), "utf8"));
  assert.equal(liveConfig.port, PORT);
  assert.equal(liveConfig.versionCheckUrl, "");

  const exited = new Promise((resolve) => daemon.on("exit", resolve));
  const stop = helmd("stop");
  assert.equal(stop.code, 0, stop.out);
  await exited;

  // Post-stop, on-disk proof: the LIVE journal.db is fresh (re-init, not
  // repair — zero rows, clean replay) and the OLD corrupted one survives
  // untouched inside the quarantined copy (never deleted).
  const freshDb = openJournal(join(TMP, "journal.db"));
  assert.deepEqual(streamHeads(freshDb), [], "the re-inited journal starts empty");
  assert.equal(replayVerify(freshDb).ok, true);
  freshDb.close();

  const oldDb = openJournal(join(quarantinePath, "journal.db"));
  assert.equal(replayVerify(oldDb).ok, false, "the quarantined copy is still the same broken journal, untouched");
  assert.equal(replayVerify(oldDb).brokenAt.seq, BROKEN_SEQ);
  oldDb.close();
});
