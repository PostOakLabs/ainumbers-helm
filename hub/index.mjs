#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// helmd — local-first control plane hub daemon. Loopback REST+SSE (D8
// hardened) + named-pipe/UDS CLI channel + doctor self-check.
import { loadConfig } from "./config.mjs";
import { loadOrCreateToken, pairingUrl, createPairingNonce } from "./token.mjs";
import { createHelmServer, bindOrExit, DAEMON_VERSION } from "./server.mjs";
import { loadOrCreateKeys } from "./keys.mjs";
import { fingerprintPublicKeyDer } from "./challenge.mjs";
import { createCliChannel, cliChannelPath } from "./cli-channel.mjs";
import { runDoctor } from "./doctor.mjs";
import { log } from "./log.mjs";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { platform } from "node:os";
import { createConnection } from "node:net";
import { statePath } from "./state-dir.mjs";
import { openJournal, replayVerify } from "./journal.mjs";
import { installAutostart, uninstallAutostart, isAutostartInstalled, autostartLocation } from "./autostart.mjs";

// No "open" package (zero-dep, D2) — shell out to each OS's native opener.
// Best-effort: a failure here (headless box, no default browser configured)
// is a warning, never fatal — the printed pairing URL is always the fallback.
//
// HELM-WIN-INSTALL-1: the pairing URL always contains `&pair=` and `&fp=`
// query params. `cmd /c start "" <url>` hands the url to cmd.exe, which
// parses `&` as a command separator REGARDLESS of the argv-level quoting
// execFileSync applies — cmd splits "...token=x&pair=y&fp=z" into three
// commands and the last two fail with "'pair' is not recognized...". This
// silently killed auto-open on every Windows run (not just non-first-run —
// see the isFirstRun/--open gate below, a separate bug). rundll32's
// url.dll,FileProtocolHandler entry point opens the default browser without
// going through cmd.exe's command-line grammar at all, so it isn't exposed
// to this class of bug.
function openBrowser(url) {
  try {
    const plat = platform();
    if (plat === "win32") execFileSync("rundll32", ["url.dll,FileProtocolHandler", url], { stdio: "ignore" });
    else if (plat === "darwin") execFileSync("open", [url], { stdio: "ignore" });
    else execFileSync("xdg-open", [url], { stdio: "ignore" });
  } catch (err) {
    log.warn("could not auto-open browser — open the pairing URL above manually", { error: String(err?.message || err) });
  }
}

async function cmdDoctor() {
  const report = await runDoctor();
  for (const c of report.checks) {
    console.log(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail !== undefined ? `  (${c.detail})` : ""}`);
  }
  process.exit(report.ok ? 0 : 1);
}

async function cmdStart({ open = false } = {}) {
  const config = loadConfig();
  const isFirstRun = !existsSync(statePath("token"));
  const token = loadOrCreateToken();
  const identityKeys = loadOrCreateKeys();
  // R15-F1 fix: fingerprint of the daemon's OWN identity key, minted only
  // here (never derivable by a port squatter) and carried into every
  // pairing link so the browser can pin it — see token.mjs pairingUrl.
  const identityFingerprint = fingerprintPublicKeyDer(
    identityKeys.ed25519.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  );

  // D6: replay-journal-on-restart integrity check. A daemon must never come
  // up serving a journal it can't prove is unbroken. Stays open for the
  // process lifetime — the H4 run engine (HELM-P2-U4) needs the same handle.
  const journalPath = statePath("journal.db");
  const db = openJournal(journalPath);
  const replay = replayVerify(db);
  if (!replay.ok) {
    db.close();
    log.error("journal replay integrity check FAILED — refusing to start", { brokenAt: replay.brokenAt });
    process.exit(1);
  }
  log.info("journal replay integrity check passed");

  const server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, db, identityKeys, versionCheckUrl: config.versionCheckUrl });
  // P3-D9: refuse to start on a squatted port — never silently bind
  // elsewhere. Must resolve BEFORE the CLI channel opens or any browser tab
  // is auto-launched, or a squatted port would open onto whatever's
  // actually listening there instead of failing loudly.
  const bound = await bindOrExit(server, config.port);
  if (!bound) {
    db.close();
    process.exit(1);
  }

  createCliChannel({
    health: () => ({ status: "ok" }),
    // HELM-P2-B8 / DEC-3: the ONLY re-pair path. Gated by the pipe's OS ACL
    // (same-user), never by an HTTP endpoint — an unauthenticated HTTP route
    // that hands out the token would be reachable by any local process. Opens
    // the browser server-side (same code path as first-run) and also returns
    // the URL so the CLI can print it for headless/no-DE sessions.
    pair: () => {
      const u = pairingUrl(token, config.port, createPairingNonce(), identityFingerprint);
      openBrowser(u);
      return { url: u };
    },
    // `helmd stop` / `helmd status`: helmd has no window, no tray icon and no
    // taskbar presence, so before these existed the only way to stop it was
    // Task Manager or kill(1), and there was no way at all to ask whether it
    // was running or whether autostart was installed. Both live on the CLI
    // channel, never on HTTP — same reasoning as `pair` above: an HTTP verb
    // that shuts the daemon down would be reachable by any local process, and
    // server.mjs's "no side effects on GET" invariant exists to be kept.
    stop: () => {
      // Reply first, exit on a later tick, or the CLI sees ECONNRESET instead
      // of an acknowledgement and reports a failure for a successful stop.
      setTimeout(() => process.exit(0), 50);
      return { stopping: true, pid: process.pid };
    },
    status: () => ({
      running: true,
      pid: process.pid,
      port: config.port,
      version: DAEMON_VERSION,
      autostart: isAutostartInstalled(),
      autostartLocation: autostartLocation(),
    }),
  }, { port: config.port });

  log.info("helmd started", { port: config.port });
  const url = pairingUrl(token, config.port, createPairingNonce(), identityFingerprint);
  console.log(url);
  console.log("(paste this into your browser if it did not open automatically)");
  console.log("");
  console.log("Helm is running. Stop it with `helmd stop`, check it with `helmd status`.");

  // HELM-WIN-INSTALL-1: this used to auto-open ONLY on first run
  // (`isFirstRun || open`) — every later start (including the very next
  // double-click after a crash, or after closing the tab) printed the URL
  // to a console window a double-click never leaves open long enough to
  // read, and opened nothing. Auto-open is harmless to repeat (it's just a
  // browser tab), so do it on every start; `open`/`--open` is now redundant
  // but stays as an explicit override for callers that want to force it.
  openBrowser(url);

  // HELM-P4-J4: the last CLI moment. First run also installs the per-user
  // autostart entry (macOS LaunchAgent / Windows HKCU Run key) so the next
  // launch is the OS's job, not the user's — best-effort, never fatal (an
  // unsupported platform or a sandboxed/CI environment just skips it).
  // Announced, never silent: this writes a persistence entry, and a product
  // that asks to be trusted cannot install one without saying so. Print where
  // it went and how to remove it, in the same breath.
  if (isFirstRun) {
    try {
      const result = installAutostart();
      if (result.ok) {
        console.log("");
        console.log("Helm will now start automatically when you log in.");
        console.log(`  entry:   ${autostartLocation()}`);
        console.log("  remove:  helmd uninstall");
      }
    } catch (err) {
      log.warn("autostart install failed (non-fatal)", { error: String(err?.message || err) });
    }
  }
}

// helmd uninstall: removes the autostart entry this same install wrote.
// Zoom-orphan lesson (P3 robustness #8) — an uninstall that leaves a
// LaunchAgent/Run-key pointing at a deleted binary is the failure mode this
// exists to prevent. Does not touch ~/.helm state (journal/keys/config) —
// that's a separate, deliberately manual decision the user hasn't asked for
// here.
function cmdUninstall() {
  const result = uninstallAutostart();
  if (result.supported === false) {
    console.log("helmd uninstall: no autostart entry on this platform, nothing to remove.");
  } else {
    console.log("helmd uninstall: autostart entry removed.");
  }
}

// Client side of the re-pair path (DEC-3): connects to the ALREADY-RUNNING
// daemon's pipe/socket and asks it for a fresh pairing link — never spins up
// its own server, never touches HTTP. If nothing is listening (daemon not
// started, or a stale socket file), that's a plain "start it first" error.
function callDaemon(cmd) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(cliChannelPath(loadConfig().port), () => socket.write(JSON.stringify({ cmd }) + "\n"));
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      const idx = buf.indexOf("\n");
      if (idx === -1) return;
      socket.end();
      let msg;
      try {
        msg = JSON.parse(buf.slice(0, idx));
      } catch {
        return reject(new Error("malformed response from daemon"));
      }
      if (!msg.ok) return reject(new Error(msg.error));
      resolve(msg.result);
    });
    // Settles at most once, so a post-`stop` ECONNRESET arriving after the
    // acknowledgement is already resolved is harmlessly ignored.
    socket.on("error", (err) => reject(Object.assign(new Error(err.message), { code: err.code })));
  });
}

// ENOENT (no socket file / no pipe) and ECONNREFUSED (stale socket file, no
// listener) both mean the same thing to a user: helmd isn't running. That is
// a normal state for `stop` and `status`, not an error to shout about.
function isNotRunning(err) {
  return err.code === "ENOENT" || err.code === "ECONNREFUSED";
}

async function cmdOpen() {
  try {
    const result = await callDaemon("pair");
    console.log(result.url);
  } catch (err) {
    console.error(`helmd open: ${isNotRunning(err) ? "no daemon listening (run `helmd start` first)" : err.message}`);
    process.exit(1);
  }
}

async function cmdStop() {
  try {
    await callDaemon("stop");
    console.log("helmd stopped.");
  } catch (err) {
    if (isNotRunning(err)) {
      console.log("helmd stop: not running.");
      return;
    }
    console.error(`helmd stop: ${err.message}`);
    process.exit(1);
  }
}

async function cmdStatus() {
  const describeAutostart = (installed, where) =>
    installed ? `installed (${where})` : where === null ? "not supported on this platform" : "not installed";
  try {
    const r = await callDaemon("status");
    console.log(`helmd: running (pid ${r.pid})`);
    console.log(`  port       ${r.port}`);
    console.log(`  version    ${r.version}`);
    console.log(`  autostart  ${describeAutostart(r.autostart, r.autostartLocation)}`);
    console.log("  pairing    helmd open");
    console.log("  stop       helmd stop");
  } catch (err) {
    if (isNotRunning(err)) {
      // Not an error the user needs a stack trace for — but still exit
      // non-zero so a script can branch on it.
      console.log("helmd: not running.");
      console.log(`  autostart  ${describeAutostart(isAutostartInstalled(), autostartLocation())}`);
      console.log("  start      helmd start");
      process.exit(1);
    }
    console.error(`helmd status: ${err.message}`);
    process.exit(1);
  }
}

const args = process.argv.slice(2);
const cmd = args[0] || "start";
if (cmd === "doctor") await cmdDoctor();
else if (cmd === "start") await cmdStart({ open: args.includes("--open") });
else if (cmd === "open") await cmdOpen();
else if (cmd === "stop") await cmdStop();
else if (cmd === "status") await cmdStatus();
else if (cmd === "uninstall") cmdUninstall();
else {
  console.error(`helmd: unknown command "${cmd}" (expected: start | stop | status | doctor | open | uninstall)`);
  process.exit(1);
}
