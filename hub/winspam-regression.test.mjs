// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// HELM-WINSPAM-1: helmd used to shell out to the OS browser-opener on EVERY
// `helmd start` — including ones with no human watching (autostart re-firing
// at login, a crash/restart loop). Any run of restarts opened one browser
// window per restart with no ceiling; Tim disabled Helm entirely over this
// (2026-08-03 bug report, "spammed localhost dashboard windows"). Fixed in
// index.mjs's cmdStart: the opener now only fires on a genuine first run (no
// token on disk yet) or an explicit `--open`.
//
// This is an E2E test, same shape as cli-verbs.test.mjs (top-level-await CLI
// entry, can't be unit tested by import). Like every suite in this repo it
// keeps HELM_NO_OPEN=1 set — stubbing the real OS opener binary (rundll32 et
// al.) on PATH instead is not reliable on Windows (System32 wins the search
// order over anything prepended to PATH) and would risk a headless test box
// actually hijacking whatever browser is installed there. What it observes
// instead is openBrowser's own "auto-opening browser tab" log line, which
// index.mjs fires unconditionally BEFORE the HELM_NO_OPEN check — so the
// signal survives suppression and still proves whether the call site's
// (isFirstRun || open) gate let execution reach openBrowser() at all, which
// is exactly the fix under test.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const TMP = mkdtempSync(join(tmpdir(), "helm-winspam-"));
process.env.HELM_HOME = TMP;

const PORT = 41780;
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: `http://127.0.0.1:${PORT}`, versionCheckUrl: "" }));

// Pre-creating the token, same trick cli-verbs.test.mjs uses, is what makes
// every `start` below a RETURNING run — exactly what autostart/a restart
// loop produces. A genuine first run is covered by the "positive control"
// test at the bottom (no pre-seeded token there).
const { loadOrCreateToken } = await import("./token.mjs");
loadOrCreateToken();

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
const ENV = { ...process.env, HELM_HOME: TMP, HELM_NO_OPEN: "1" };

let daemon;
after(() => {
  if (daemon && daemon.exitCode === null) daemon.kill();
  rmSync(TMP, { recursive: true, force: true });
});

function waitForRunning(child) {
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`daemon did not report ready:\n${out}`)), 20000);
    child.stdout.on("data", (c) => {
      out += c.toString("utf8");
      if (out.includes("Helm is running.")) {
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

// "close", not "exit" — "exit" can fire before the stdout pipe has finished
// draining its last buffered chunk, and the log line under test here is
// printed right at the tail end of a boot, so a test reading `out` on
// "exit" raced it and saw a truncated buffer.
function waitForClose(child) {
  return new Promise((resolve) => child.on("close", resolve));
}

test("3 returning-run restarts, no --open: the browser opener never fires", async () => {
  let allOutput = "";
  for (let i = 0; i < 3; i++) {
    daemon = spawn(process.execPath, [ENTRY, "start"], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
    daemon.stdout.on("data", (c) => (allOutput += c.toString("utf8")));
    await waitForRunning(daemon);
    execFileSync(process.execPath, [ENTRY, "stop"], { env: ENV });
    await waitForClose(daemon);
  }
  assert.equal(
    (allOutput.match(/auto-opening browser tab/g) || []).length,
    0,
    `browser opener fired on a returning-run restart — the spam bug is back:\n${allOutput}`
  );
});

test("positive control: a genuine first run DOES open a tab (proves the log signal works)", async () => {
  const freshHome = mkdtempSync(join(tmpdir(), "helm-winspam-firstrun-"));
  writeFileSync(join(freshHome, "config.json"), JSON.stringify({ port: PORT + 1, allowedOrigin: `http://127.0.0.1:${PORT + 1}`, versionCheckUrl: "" }));
  const freshEnv = { ...ENV, HELM_HOME: freshHome };
  let out = "";
  const child = spawn(process.execPath, [ENTRY, "start"], { env: freshEnv, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (c) => (out += c.toString("utf8")));
  try {
    await waitForRunning(child);
    execFileSync(process.execPath, [ENTRY, "stop"], { env: freshEnv });
    await waitForClose(child);
    assert.match(out, /auto-opening browser tab/, "a genuine first run should still open a tab — the gate is now over-strict");
  } finally {
    rmSync(freshHome, { recursive: true, force: true });
  }
});
