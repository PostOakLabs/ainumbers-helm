// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-ANCHOR-DEFAULT-FLIP-1: proves the boot-log warn is (a) present when
// anchoring is off — the default — and (b) printed EXACTLY ONCE per boot,
// never once per checkpoint. Before this row, this exact scenario (a real
// `helmd start` boot with anchoring off) printed no warning at all — phil's
// finding was that a doctor-only notice leaves the "operator never runs
// doctor again" case silent, which is the mainline case for a
// no-recurring-maintenance product (SO #0).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const TMP = mkdtempSync(join(tmpdir(), "helm-anchor-default-flip-boot-"));
const PORT = 42201;
const ORIGIN = `http://127.0.0.1:${PORT}`;
// Deliberately NOT setting anchorOnCheckpoint — proving the default (unset
// ⇒ false) is what triggers the warn, not an explicit opt-out.
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "", idleTimeoutMs: 999999 }));

process.env.HELM_HOME = TMP;
const { openJournal, appendEntry } = await import("./journal.mjs");

{
  const db = openJournal(join(TMP, "journal.db"));
  appendEntry(db, {
    streamId: "run-1",
    kind: "execution_state",
    entry: {
      period_start: "2026-07-26T00:00:00.000Z",
      period_end: "2026-07-26T00:00:01.000Z",
      reference_db_version: "kernels@2026-07-26",
      triggering_input_digest: "sha256:" + "e".repeat(64),
      humans_involved: [],
      state: "queued",
    },
  });
  db.close();
}

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
const ENV = { ...process.env, HELM_HOME: TMP, HELM_NO_OPEN: "1" };

let daemon;
after(() => {
  if (daemon && daemon.exitCode === null) daemon.kill();
  rmSync(TMP, { recursive: true, force: true });
});

function helmd(...args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [ENTRY, ...args], { env: ENV, encoding: "utf8" }) };
  } catch (err) {
    return { code: err.status, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

function waitForMarker(child, marker) {
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`daemon did not print "${marker}":\n${out}`)), 20000);
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

const WARN_MSG = "checkpoint anchoring is disabled";

test("helmd start: prints the anchoring-disabled warn line exactly once when anchorOnCheckpoint defaults off", async () => {
  daemon = spawn(process.execPath, [ENTRY, "start"], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  const startupOutput = await waitForMarker(daemon, "checkpoint saved without a live anchor");

  const warnLines = startupOutput
    .split("\n")
    .filter((line) => line.includes(WARN_MSG));
  assert.equal(warnLines.length, 1, `expected exactly one warn line, got ${warnLines.length}:\n${startupOutput}`);
  assert.match(warnLines[0], /"level":"warn"/);

  const exited = new Promise((resolve) => daemon.on("exit", resolve));
  const stop = helmd("stop");
  assert.equal(stop.code, 0, stop.out);
  await exited;
});
