// End-to-end cover for `helmd start` / `status` / `stop`. These verbs only
// exist as a CLI entry point with top-level await, so they cannot be unit
// tested by import — the daemon has to actually run.
//
// Two safety properties this file depends on, both deliberate:
//   * HELM_HOME is a temp dir and the port is unique, so the Windows named
//     pipe (scoped by port, see cli-channel.mjs) and the unix socket (scoped
//     by HELM_HOME) can never reach a real helmd. Without that scoping, a
//     `stop` here could have killed a developer's running daemon.
//   * The token file is created BEFORE the daemon starts, so isFirstRun is
//     false and the run never installs a real autostart entry. Tests must
//     not write to the registry or ~/Library/LaunchAgents.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";

const TMP = mkdtempSync(join(tmpdir(), "helm-cli-verbs-"));
process.env.HELM_HOME = TMP;

const PORT = 41778;
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: `http://127.0.0.1:${PORT}`, versionCheckUrl: "" }));

// Creating the token here is what makes the daemon's first real start a
// NON-first run — see the autostart note above.
const { loadOrCreateToken } = await import("./token.mjs");
loadOrCreateToken();

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
// HELM_NO_OPEN: `helmd start` opens a browser tab on EVERY start (hub/index.mjs),
// so without this the suite hijacks the developer's browser once per run — and a
// pre-push hook that runs the suite does it once per push attempt.
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

test("status and stop report cleanly when no daemon is running", () => {
  const status = helmd("status");
  assert.equal(status.code, 1, "not-running status should exit non-zero so scripts can branch on it");
  assert.match(status.out, /not running/);

  const stop = helmd("stop");
  assert.equal(stop.code, 0, "stopping an already-stopped daemon is not an error");
  assert.match(stop.out, /not running/);
});

test("start -> status -> stop round trip", async () => {
  daemon = spawn(process.execPath, [ENTRY, "start"], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  // The auto-open log line is emitted AFTER the "Helm is running." banner that
  // waitForRunning resolves on, so it needs its own accumulator rather than the
  // resolved snapshot.
  let allOutput = "";
  daemon.stdout.on("data", (c) => (allOutput += c.toString("utf8")));
  const startupOutput = await waitForRunning(daemon);

  // The start banner has to name the off switch: helmd has no window, no
  // tray and no taskbar entry, so if this line goes missing the user has no
  // way to discover that stopping it is even possible.
  assert.match(startupOutput, /helmd stop/);

  const status = helmd("status");
  assert.equal(status.code, 0);
  assert.match(status.out, /running \(pid \d+\)/);
  assert.match(status.out, new RegExp(`port\\s+${PORT}`));

  // Regression: `helmd start` auto-opens a browser tab on EVERY start, so an
  // automated caller that spawns the daemon hijacks the machine's browser. Run
  // from a pre-push hook, that is one tab per push attempt. HELM_NO_OPEN (set in
  // ENV above) is the opt-out; this asserts it is honoured, not merely set.
  // Polled, not sampled: this line is written after the "Helm is running."
  // banner that waitForRunning resolves on, and the child's stdout is a pipe.
  for (let i = 0; i < 60 && !/browser auto-open suppressed/.test(allOutput); i++) {
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.match(allOutput, /browser auto-open suppressed/);

  const exited = new Promise((resolve) => daemon.on("exit", resolve));
  const stop = helmd("stop");
  // Regression guard: the daemon replies and only then exits. If it exited
  // first, the CLI would see ECONNRESET and report a failure for a stop that
  // actually succeeded.
  assert.equal(stop.code, 0, stop.out);
  assert.match(stop.out, /helmd stopped/);
  assert.equal(await exited, 0);

  assert.match(helmd("status").out, /not running/);
});
