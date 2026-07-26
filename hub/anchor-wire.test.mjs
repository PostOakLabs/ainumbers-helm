// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-ANCHOR-WIRE-1: end-to-end proof that a REAL `helmd start` boot no
// longer hardcodes `anchors: []` on the checkpoint it saves. Every piece
// this wires together (anchorForCheckpoint's failure handling, HELM-TSA-1's
// verifier, the schema-widened queue marker) already shipped and is already
// covered elsewhere — this file's only job is proving the boot path in
// hub/index.mjs actually calls it, per row `HELM-ANCHOR-WIRE-1`'s "show RED
// before GREEN" requirement (RETRO-ORCH-2026-07-25 §4): before this WU,
// this exact test failed — `latestCheckpoint(db).envelope`'s
// `predicate.anchors` was `[]`. Runs fully offline (config.anchorOnCheckpoint:
// false), so it's deterministic in CI regardless of egress — the
// reachable-relay and relay-failure code paths are unit-tested with
// fetchImpl injection in checkpoint.test.mjs, not re-tested here.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const TMP = mkdtempSync(join(tmpdir(), "helm-anchor-wire-e2e-"));
const PORT = 42200;
const ORIGIN = `http://127.0.0.1:${PORT}`;
// anchorOnCheckpoint: false — the config-level zero-egress switch this row
// adds (hub/config.mjs) — makes the run deterministic without depending on
// real network reachability from a CI sandbox. Real-relay and relay-failure
// behavior is covered by checkpoint.test.mjs's fetchImpl-injected tests.
writeFileSync(join(TMP, "config.json"), JSON.stringify({
  port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "", idleTimeoutMs: 999999, anchorOnCheckpoint: false,
}));

process.env.HELM_HOME = TMP;
const { openJournal, appendEntry } = await import("./journal.mjs");
const { latestCheckpoint } = await import("./checkpoint.mjs");

// A non-empty journal is required for cmdStart's checkpoint-taking branch
// (`heads.length > 0`) to fire at all.
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

// Waits for the anchoring background task's own log line (see
// checkpoint.mjs's buildAnchoredCheckpoint), not just "cli channel
// listening" — that line prints BEFORE the fire-and-forget anchor/save
// kicked off in index.mjs resolves, which is the whole non-blocking-boot
// point of this row; the checkpoint isn't on disk yet at that moment.
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

test("helmd start: the checkpoint it saves carries a real anchor marker, never the historical anchors: []", async () => {
  daemon = spawn(process.execPath, [ENTRY, "start"], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  const startupOutput = await waitForMarker(daemon, "checkpoint saved without a live anchor");
  assert.match(startupOutput, /Helm is running\./, "boot must not have stalled waiting on anchoring");

  // The daemon is genuinely up (bindOrExit succeeded) independent of the
  // anchoring background task — proves anchoring did not block startup.
  const status = helmd("status");
  assert.equal(status.code, 0, status.out);
  assert.match(status.out, new RegExp(`port\\s+${PORT}`));

  const exited = new Promise((resolve) => daemon.on("exit", resolve));
  const stop = helmd("stop");
  assert.equal(stop.code, 0, stop.out);
  await exited;

  const db = openJournal(join(TMP, "journal.db"));
  const checkpoint = latestCheckpoint(db);
  assert.ok(checkpoint, "a checkpoint must have been saved");
  const statement = JSON.parse(Buffer.from(checkpoint.envelope.payload, "base64").toString("utf8"));
  const predicate = statement.predicate;
  assert.notDeepEqual(predicate.anchors, [], "anchors[] must never be the historical hardcoded empty array");
  assert.equal(predicate.anchors.length, 1);
  assert.equal(predicate.anchors[0].type, "skipped", "anchorOnCheckpoint: false must route through the offline/skipped path, not a real attempt");
  assert.equal(predicate.anchors[0].reason, "egress_blocked");
  db.close();
});
