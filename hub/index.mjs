#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// helmd — local-first control plane hub daemon. Loopback REST+SSE (D8
// hardened) + named-pipe/UDS CLI channel + doctor self-check.
import { loadConfig } from "./config.mjs";
import { loadOrCreateToken, pairingUrl, createPairingNonce } from "./token.mjs";
import { createHelmServer, bindOrExit, DAEMON_VERSION } from "./server.mjs";
import { loadOrCreateKeys } from "./keys.mjs";
import { loadOrCreateHaIdentity } from "./ha-identity.mjs";
import { fingerprintPublicKeyDer } from "./challenge.mjs";
import { createCliChannel, cliChannelPath } from "./cli-channel.mjs";
import { runDoctor } from "./doctor.mjs";
import { log } from "./log.mjs";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { platform } from "node:os";
import { createConnection } from "node:net";
import { statePath, stateDir } from "./state-dir.mjs";
import { openJournal, replayVerify, replayVerifyFrom, recordFullVerification, streamHeads } from "./journal.mjs";
import { quarantineStateDir } from "./recovery.mjs";
import { buildAnchoredCheckpoint, saveCheckpoint, latestCheckpoint, verifyCheckpointSignature } from "./checkpoint.mjs";
import { publicKeysOf } from "./keys.mjs";
import { installAutostart, uninstallAutostart, isAutostartInstalled, autostartLocation } from "./autostart.mjs";
import { installShortcut, uninstallShortcut, isShortcutInstalled, shortcutLocation } from "./shortcut.mjs";
import { createIdleTimer } from "./idle-timer.mjs";
import { getSseConnectionCount, getRunsInFlightCount } from "./server.mjs";
import { isPairingWindowOpen } from "./token.mjs";
import { isBackupInFlight } from "./backup.mjs";

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
// HELM_NO_OPEN: automated callers (the test suite, CI, a scripted install)
// start a real daemon and must not hijack the machine's browser to do it.
// Every `helmd start` opens a tab (see the call site below), so a test that
// spawns the daemon opened a tab on the developer's desktop on every run, and
// a suite that spawns it repeatedly opened one every few minutes. Opt-out, not
// opt-in: a human running `helmd start` by hand still gets the tab, which is
// the behaviour the auto-open exists for. Also gates the first-run autostart/
// shortcut installation below (same "automated caller must not touch the
// machine persistently" contract) — HELM-JOURNAL-REPAIR-1's recovery boot
// re-enters first-run (a quarantined state dir has no token yet), so a test
// that exercises that path needs the same opt-out or it writes a real
// registry/LaunchAgent entry on the test machine.
function openBrowser(url) {
  if (process.env.HELM_NO_OPEN === "1") {
    log.info("browser auto-open suppressed by HELM_NO_OPEN", { url });
    return;
  }
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

async function cmdStart({ open = false, _recoveredFrom = null } = {}) {
  const config = loadConfig();
  const isFirstRun = !existsSync(statePath("token"));
  const token = loadOrCreateToken();
  const identityKeys = loadOrCreateKeys();
  const haIdentity = await loadOrCreateHaIdentity();
  // R15-F1 fix: fingerprint of the daemon's OWN identity key, minted only
  // here (never derivable by a port squatter) and carried into every
  // pairing link so the browser can pin it — see token.mjs pairingUrl.
  const identityFingerprint = fingerprintPublicKeyDer(
    identityKeys.ed25519.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  );

  // D6/§9: a daemon must never come up serving a journal it can't prove is
  // unbroken — but a FULL genesis-to-head replay on every boot is unbounded
  // (O(n) in total journal size, an eventual OOM on a long-lived install).
  // §9's fix: verify from the last signed checkpoint forward instead of from
  // the beginning, and only fall back to a full replay when there's no
  // checkpoint yet, or it fails its own signature/consistency check, or (per
  // config.anchorRequired, §9.4) it isn't anchored. `helmd doctor` still
  // does the unconditional full replay — that's the tool for "prove the
  // whole history," not every boot. Stays open for the process lifetime —
  // the H4 run engine (HELM-P2-U4) needs the same handle.
  const journalPath = statePath("journal.db");
  const db = openJournal(journalPath);
  const publicKeys = publicKeysOf(identityKeys);
  const checkpoint = latestCheckpoint(db);
  let sig = checkpoint ? verifyCheckpointSignature(checkpoint, publicKeys) : null;
  const anchored = sig?.predicate?.anchors?.length > 0;
  const canFastPath = !!(sig?.valid && (anchored || !config.anchorRequired));

  let verified;
  if (canFastPath) {
    verified = replayVerifyFrom(db, sig.predicate.streams);
    if (verified.ok) log.info("journal replay integrity check passed (fast path, since checkpoint)", { checkpointSeq: checkpoint.checkpointSeq });
  } else {
    verified = replayVerify(db);
    if (verified.ok) {
      recordFullVerification(db);
      log.info("journal replay integrity check passed (full replay)", {
        reason: !checkpoint ? "no_checkpoint" : !sig?.valid ? sig.reason : "checkpoint_not_anchored",
      });
    }
  }
  if (!verified.ok) {
    db.close();
    log.error("journal replay integrity check FAILED", { brokenAt: verified.brokenAt });
    if (_recoveredFrom) {
      // Defense in depth, should never fire: a freshly quarantined+re-inited
      // journal has zero rows, so replayVerify trivially passes. A second
      // failure right after recovery means something deeper than a broken
      // journal is wrong (e.g. an unwritable state dir) — refuse loudly
      // instead of quarantining forever.
      log.error("journal replay integrity check failed again immediately after quarantine+reinit — refusing to start", {
        brokenAt: verified.brokenAt,
      });
      process.exit(1);
    }
    // HELM-JOURNAL-REPAIR-1: a broken journal used to be a dead end — no
    // restore path exists for an install that never booted clean once
    // (backup.mjs's restore needs a live daemon to have taken a backup from).
    // Quarantine the whole state dir (never delete) and re-init fresh,
    // exactly what Tim's confirmed manual recovery does by hand.
    const recovery = quarantineStateDir(stateDir(), verified.brokenAt);
    log.error("broken state quarantined (not deleted); re-initializing fresh state and continuing boot", recovery);
    return cmdStart({ open, _recoveredFrom: recovery });
  }

  // Advance the checkpoint frontier every boot a verification just proved
  // clean, so the NEXT boot's fast path only has to replay what's been
  // appended since THIS boot — the delta stays bounded by one uptime, not by
  // the daemon's whole lifetime.
  //
  // HELM-ANCHOR-WIRE-1: anchoring is an RFC 3161 network round trip
  // (anchor-client.mjs → anchor.ainumbers.co) — helmd's own readiness must
  // never depend on a TSA relay's latency or availability, so this is kicked
  // off (see below, past bindOrExit) only AFTER the server is already
  // listening, and never awaited by the boot path itself. A relay failure
  // can't fail it either way: buildAnchoredCheckpoint's anchorForCheckpoint
  // call already turns "unreachable"/"egress blocked"/"HTTP error" into a
  // schema-valid queued/skipped marker instead of throwing (§5 exit-gate #1).
  const heads = streamHeads(db);
  const nextCheckpointSeq = heads.length > 0 ? (checkpoint?.checkpointSeq ?? 0) + 1 : null;

  // §18: helmd stops itself after config.idleTimeoutMs (default 2 minutes,
  // §18.3) with nothing going on. "Going on" is deliberately broader than
  // "an HTTP request just landed" — an open SSE tab, a run mid-execution, a
  // just-minted pairing link, or a backup/export must all hold the daemon
  // open even if no new authenticated request arrives during them (§18.2).
  // Built before createHelmServer so its reset() can be wired in as the
  // server's onAuthenticated hook below.
  const idleTimer = createIdleTimer({
    timeoutMs: config.idleTimeoutMs,
    isSuppressed: () => getSseConnectionCount() > 0 || getRunsInFlightCount() > 0 || isPairingWindowOpen() || isBackupInFlight(),
    onIdle: () => {
      log.info(`helmd: idle for ${config.idleTimeoutMs}ms — stopping (see \`helmd status\` / Operate for how to restart)`);
      // Same reply-then-exit discipline as the CLI `stop` verb (§2's
      // ordering guarantee) even though nothing is waiting on a reply here —
      // the delay gives this log line's write a tick to land before exit.
      setTimeout(() => process.exit(0), 50);
    },
  });

  const server = createHelmServer({
    port: config.port,
    allowedOrigin: config.allowedOrigin,
    token,
    db,
    identityKeys,
    haIdentity,
    versionCheckUrl: config.versionCheckUrl,
    idleTimeoutMs: config.idleTimeoutMs,
    onAuthenticated: () => idleTimer.reset(),
  });
  // P3-D9: refuse to start on a squatted port — never silently bind
  // elsewhere. Must resolve BEFORE the CLI channel opens or any browser tab
  // is auto-launched, or a squatted port would open onto whatever's
  // actually listening there instead of failing loudly.
  const bound = await bindOrExit(server, config.port);
  if (!bound) {
    db.close();
    process.exit(1);
  }

  // Fire-and-forget, deliberately not awaited — see the comment above
  // nextCheckpointSeq. Any unexpected failure here (not just a relay
  // failure — buildAnchoredCheckpoint already handles those — but e.g. a
  // db write error) is caught and logged, never an unhandled rejection and
  // never a reason the daemon that's already listening should go down.
  if (nextCheckpointSeq !== null) {
    buildAnchoredCheckpoint(db, {
      checkpointSeq: nextCheckpointSeq,
      keys: identityKeys,
      offline: !config.anchorOnCheckpoint,
    })
      .then((built) => saveCheckpoint(db, built))
      .catch((err) => {
        log.error("checkpoint anchoring/save failed unexpectedly (checkpoint not advanced this boot)", {
          checkpointSeq: nextCheckpointSeq,
          error: String(err?.message || err),
        });
      });
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
      shortcut: isShortcutInstalled(),
      shortcutLocation: shortcutLocation(),
      // §18.4: announced here too, not just Operate — `helmd status` is the
      // zero-CLI-else escape hatch this project's headless/no-DE users have.
      idleTimeoutMs: config.idleTimeoutMs,
    }),
  }, { port: config.port });

  // §18.2 insertion point: the timer starts counting down from here, the
  // first moment there's a running daemon with nothing yet in flight.
  // Without this call the countdown would never begin until the first
  // authenticated request — silently doubling the effective idle window on
  // an install nobody ever opens a browser tab against.
  idleTimer.reset();

  log.info("helmd started", { port: config.port });
  const url = pairingUrl(token, config.port, createPairingNonce(), identityFingerprint);
  console.log(url);
  console.log("(paste this into your browser if it did not open automatically)");
  console.log("");
  console.log("Helm is running. Stop it with `helmd stop`, check it with `helmd status`.");
  // §18.4: said out loud at boot, not just on demand — the consequence
  // (a bookmark reaching nothing until relaunched) is one Tim explicitly
  // accepted contingent on it never being a silent surprise.
  console.log(`Helm stops automatically after ${Math.round(config.idleTimeoutMs / 1000)}s idle — a Start Menu / Applications launch brings it back.`);

  // HELM-JOURNAL-REPAIR-1: the only surface a double-click launch leaves
  // behind once the window closes is whatever got printed before that —
  // so a recovered boot says so here, in the same banner as the off-switch
  // reminder above, not just in a log line nobody's console stays open to see.
  if (_recoveredFrom) {
    console.log("");
    console.log("A corrupted journal was found and quarantined — nothing was lost, since it never finished starting cleanly.");
    console.log(`  quarantined state: ${_recoveredFrom.quarantinePath}`);
    console.log(`  failure details:   ${_recoveredFrom.crashLogPath}`);
  }

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
  if (isFirstRun && process.env.HELM_NO_OPEN !== "1") {
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
    // Same first-run moment, same announce-and-removable contract: give the
    // user something to click. winget's portable installer type cannot create
    // one, so without this a completed install leaves nothing on the machine
    // the user can find. Best-effort — a failed shortcut never blocks a
    // working daemon.
    try {
      const result = installShortcut();
      if (result.ok) {
        console.log("");
        console.log("A Helm shortcut has been added to your Start Menu.");
        console.log(`  entry:   ${result.path}`);
        console.log("  remove:  helmd uninstall");
      }
    } catch (err) {
      log.warn("start menu shortcut failed (non-fatal)", { error: String(err?.message || err) });
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
  // Anything first run installs, uninstall removes — the same orphan lesson.
  // A Start Menu entry pointing at a deleted binary is the desktop version of
  // the leftover LaunchAgent this function exists to prevent.
  const shortcut = uninstallShortcut();
  if (shortcut.ok) console.log("helmd uninstall: Start Menu shortcut removed.");
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
  const describeEntry = (installed, where) =>
    installed ? `installed (${where})` : where === null ? "not supported on this platform" : "not installed";
  try {
    const r = await callDaemon("status");
    console.log(`helmd: running (pid ${r.pid})`);
    console.log(`  port       ${r.port}`);
    console.log(`  version    ${r.version}`);
    console.log(`  autostart  ${describeEntry(r.autostart, r.autostartLocation)}`);
    console.log(`  shortcut   ${describeEntry(r.shortcut, r.shortcutLocation)}`);
    console.log(`  idle stop  after ${Math.round(r.idleTimeoutMs / 1000)}s idle (configurable in ~/.helm/config.json); relaunch via Start Menu / Applications`);
    console.log("  pairing    helmd open");
    console.log("  stop       helmd stop");
  } catch (err) {
    if (isNotRunning(err)) {
      // Not an error the user needs a stack trace for — but still exit
      // non-zero so a script can branch on it.
      console.log("helmd: not running.");
      console.log(`  autostart  ${describeEntry(isAutostartInstalled(), autostartLocation())}`);
      console.log(`  shortcut   ${describeEntry(isShortcutInstalled(), shortcutLocation())}`);
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
