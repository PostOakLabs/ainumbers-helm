#!/usr/bin/env node
// helmd — local-first control plane hub daemon. Loopback REST+SSE (D8
// hardened) + named-pipe/UDS CLI channel + doctor self-check.
import { loadConfig } from "./config.mjs";
import { loadOrCreateToken, pairingUrl, createPairingNonce } from "./token.mjs";
import { createHelmServer, bindOrExit } from "./server.mjs";
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
import { installAutostart, uninstallAutostart } from "./autostart.mjs";

// No "open" package (zero-dep, D2) — shell out to each OS's native opener.
// Best-effort: a failure here (headless box, no default browser configured)
// is a warning, never fatal — the printed pairing URL is always the fallback.
function openBrowser(url) {
  try {
    const plat = platform();
    if (plat === "win32") execFileSync("cmd", ["/c", "start", "", url], { stdio: "ignore" });
    else if (plat === "darwin") execFileSync("open", [url], { stdio: "ignore" });
    else execFileSync("xdg-open", [url], { stdio: "ignore" });
  } catch (err) {
    log.warn("could not auto-open browser", { error: String(err?.message || err) });
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
  });

  log.info("helmd started", { port: config.port });
  const url = pairingUrl(token, config.port, createPairingNonce(), identityFingerprint);
  console.log(url);

  // First-run zero-CLI-copy-paste onboarding (HELM-U4): the pairing link
  // opens itself. `--open` forces the same behavior on any later start
  // (e.g. a future `helm open` wrapper shelling out to `helmd start --open`).
  if (isFirstRun || open) openBrowser(url);

  // HELM-P4-J4: the last CLI moment. First run also installs the per-user
  // autostart entry (macOS LaunchAgent / Windows HKCU Run key) so the next
  // launch is the OS's job, not the user's — best-effort, never fatal (an
  // unsupported platform or a sandboxed/CI environment just skips it).
  if (isFirstRun) {
    try {
      installAutostart();
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
function cmdOpen() {
  const path = cliChannelPath();
  const socket = createConnection(path, () => socket.write(JSON.stringify({ cmd: "pair" }) + "\n"));
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
      console.error("helmd open: malformed response from daemon");
      process.exit(1);
    }
    if (!msg.ok) {
      console.error(`helmd open: ${msg.error}`);
      process.exit(1);
    }
    console.log(msg.result.url);
  });
  socket.on("error", (err) => {
    console.error(`helmd open: no daemon listening (${err.code === "ENOENT" || err.code === "ECONNREFUSED" ? "run `helmd start` first" : err.message})`);
    process.exit(1);
  });
}

const args = process.argv.slice(2);
const cmd = args[0] || "start";
if (cmd === "doctor") await cmdDoctor();
else if (cmd === "start") await cmdStart({ open: args.includes("--open") });
else if (cmd === "open") cmdOpen();
else if (cmd === "uninstall") cmdUninstall();
else {
  console.error(`helmd: unknown command "${cmd}" (expected: start | doctor | open | uninstall)`);
  process.exit(1);
}
