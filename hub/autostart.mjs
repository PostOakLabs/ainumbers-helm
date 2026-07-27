// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Autostart: a per-user launcher so helmd survives reboots without a terminal
// ever reopening — macOS gets a LaunchAgent (RunAtLoad, visible in System
// Settings > Login Items), Windows gets an HKCU Run value. Both are per-user
// (no admin), and both are removed on uninstall (Zoom-orphan lesson, P3
// robustness #8 — a leftover autostart entry after uninstall is the failure
// mode we're avoiding). Linux has no single-user autostart convention worth
// committing to yet — no-op, `supported: false`.
//
// HELM-AUTOSTART-1: NOTHING IN THIS MODULE MAY BE CALLED WITHOUT AN EXPLICIT
// USER ACTION. It used to run unconditionally on first run (index.mjs), which
// meant opening the downloaded .exe once installed a reboot-surviving
// persistence entry with no prompt — the announcement that was supposed to
// cover it printed to a console window a double-click closes before anyone
// reads it. That is a consent bypass, and it is the exact shape AV/EDR
// heuristics classify as PUA. The only callers now are the pairing tab's
// opt-in toggle (POST /autostart, default OFF) and `helmd uninstall`.
//
// KeepAlive is deliberately FALSE. It was true (crash self-heal), which
// meant `helmd stop`, a Quit button, and plain kill(1) were all lies on
// macOS: launchd relaunched the process immediately and the user had no way
// to turn helmd off short of `helmd uninstall`. Software the user cannot
// stop is the defining behavior of an implant, and this product is sold on
// being inspectable. RunAtLoad alone gives start-on-login, which is the
// actual goal; crash recovery is worth less than a working off switch.
import { existsSync, mkdirSync, writeFileSync, unlinkSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir, platform } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const LABEL = "co.ainumbers.helmd";
const RUN_VALUE_NAME = "AINumbersHelmd";
const HERE = dirname(fileURLToPath(import.meta.url));

// The command to relaunch helmd with, derived from how THIS process was
// invoked — works for the packaged SEA binary (`process.execPath` alone,
// argv[1] is the binary itself) and for a dev/npm checkout (`node
// .../hub/index.mjs start`).
export function autostartCommand({ execPath = process.execPath, entry = process.argv[1] } = {}) {
  const isSea = !entry || entry === execPath;
  return isSea ? { command: execPath, args: ["start"] } : { command: execPath, args: [entry, "start"] };
}

function launchAgentPath(home) {
  return join(home, "Library", "LaunchAgents", `${LABEL}.plist`);
}

function launchAgentPlist({ command, args }) {
  const programArgs = [command, ...args]
    .map((a) => `      <string>${a.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")}</string>`)
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${programArgs}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
`;
}

function installMac({ home, exec, cmd }) {
  const path = launchAgentPath(home);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, launchAgentPlist(cmd));
  // Best-effort: loads it into the current session immediately so the user
  // doesn't have to log out/in to see it self-heal. A failure here (no
  // launchd session, e.g. CI or a headless box) never blocks install — the
  // plist is written and RunAtLoad picks it up on the next real login.
  try {
    exec("launchctl", ["load", path]);
  } catch {
    // non-fatal — see comment above
  }
  return { ok: true, path };
}

function uninstallMac({ home, exec }) {
  const path = launchAgentPath(home);
  try {
    exec("launchctl", ["unload", path]);
  } catch {
    // non-fatal — may already be unloaded, or no launchd session
  }
  if (existsSync(path)) unlinkSync(path);
  return { ok: true, path };
}

function isInstalledMac({ home }) {
  return existsSync(launchAgentPath(home));
}

function quoteWin(s) {
  return `"${s.replace(/"/g, '\\"')}"`;
}

function runValueFor(cmd) {
  return [cmd.command, ...cmd.args].map(quoteWin).join(" ");
}

// The reverse of quoteWin, for the FIRST token only: the recorded Run value is
// a single string, and the only part of it we can check against the filesystem
// is the executable at its head.
function firstQuotedToken(value) {
  const s = String(value).trim();
  if (!s.startsWith('"')) return s.split(/\s+/)[0] ?? "";
  let out = "";
  for (let i = 1; i < s.length; i++) {
    if (s[i] === "\\" && s[i + 1] === '"') {
      out += '"';
      i++;
      continue;
    }
    if (s[i] === '"') break;
    out += s[i];
  }
  return out;
}

function installWindows({ exec, cmd }) {
  const value = runValueFor(cmd);
  exec("reg", ["add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", RUN_VALUE_NAME, "/t", "REG_SZ", "/d", value, "/f"]);
  return { ok: true, value };
}

function uninstallWindows({ exec }) {
  try {
    exec("reg", ["delete", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", RUN_VALUE_NAME, "/f"]);
  } catch {
    // non-fatal — already removed
  }
  return { ok: true };
}

function isInstalledWindows({ exec }) {
  try {
    exec("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", RUN_VALUE_NAME]);
    return true;
  } catch {
    return false;
  }
}

// --- HELM-AUTOSTART-1 §4: is the recorded entry still POINTING AT ANYTHING ---
//
// isInstalledWindows/isInstalledMac answer "does an entry exist", which is not
// the question a user cares about. installWindows bakes autostartCommand()'s
// path in as a literal string; move or rename the binary (three
// differently-numbered copies accumulating in Downloads is exactly how this
// was found) and the entry survives, points at a dead path, and Explorer fails
// silently at logon — while `isInstalled` keeps reporting healthy. The same
// applies to the LaunchAgent's ProgramArguments.
//
// The arming change to watch for: an auto-update that moves or renames the
// binary in place without re-calling installAutostart().

function readRecordedWindows({ execOut }) {
  let out;
  try {
    out = execOut("reg", ["query", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", RUN_VALUE_NAME]);
  } catch {
    return null; // not installed, or the hive is unreadable — same to a caller
  }
  const m = new RegExp(`^\\s*${RUN_VALUE_NAME}\\s+REG_SZ\\s+(.*)$`, "m").exec(String(out ?? ""));
  return m ? m[1].trim() : null;
}

// Pulls ProgramArguments back out of a plist we wrote ourselves. Deliberately
// not a general XML parser (zero-dep, and the only input shape is
// launchAgentPlist's own output).
export function parsePlistProgramArguments(xml) {
  const block = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(String(xml ?? ""));
  if (!block) return null;
  return [...block[1].matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) =>
    m[1].replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
  );
}

function readRecordedMac({ home }) {
  const path = launchAgentPath(home);
  if (!existsSync(path)) return null;
  let args;
  try {
    args = parsePlistProgramArguments(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
  return args && args.length ? args.join(" ") : null;
}

// One shape for every platform:
//   supported  — is autostart implemented here at all
//   installed  — an entry exists
//   stale      — an entry exists but cannot do its job
//   reason     — "ok" | "not_installed" | "unsupported" | "target_missing" |
//                "command_mismatch" | "unreadable"
//   recorded / expected — the two command strings, for a human to compare
export function autostartStatus({
  plat = platform(),
  home = homedir(),
  exec = defaultExec,
  execOut = defaultExecOut,
  cmd = autostartCommand(),
  fileExists = existsSync,
} = {}) {
  const location = autostartLocation({ plat, home });
  if (plat !== "darwin" && plat !== "win32") {
    return { supported: false, installed: false, stale: false, reason: "unsupported", location, recorded: null, expected: null };
  }

  const expected = plat === "win32" ? runValueFor(cmd) : [cmd.command, ...cmd.args].join(" ");
  const installed = plat === "win32" ? isInstalledWindows({ exec }) : isInstalledMac({ home });
  if (!installed) {
    return { supported: true, installed: false, stale: false, reason: "not_installed", location, recorded: null, expected };
  }

  const recorded = plat === "win32" ? readRecordedWindows({ execOut }) : readRecordedMac({ home });
  if (!recorded) {
    // The entry is there but we cannot read what it says — treat as stale
    // rather than healthy: an unverifiable persistence entry is precisely the
    // thing this check exists to stop reporting green.
    return { supported: true, installed: true, stale: true, reason: "unreadable", location, recorded: null, expected };
  }

  const target = plat === "win32" ? firstQuotedToken(recorded) : recorded.split(" ")[0];
  if (target && !fileExists(target)) {
    return { supported: true, installed: true, stale: true, reason: "target_missing", location, recorded, expected };
  }
  if (recorded !== expected) {
    // The target exists but is not the helmd that is running now — a second
    // copy of the binary, or a dev checkout started by hand. Worth showing;
    // NOT a failure, since the recorded entry would still start a working Helm.
    return { supported: true, installed: true, stale: false, reason: "command_mismatch", location, recorded, expected };
  }
  return { supported: true, installed: true, stale: false, reason: "ok", location, recorded, expected };
}

// Lives here, not in doctor.mjs, so its injectables (fake registry, temp
// $HOME) are reachable from a test without doctor.mjs having to grow an
// injection seam for the whole self-check.
export function autostartDoctorCheck(opts = {}) {
  const status = autostartStatus(opts);
  if (!status.supported) return { name: "autostart_entry_valid", pass: true, detail: "not supported on this platform" };
  if (!status.installed) return { name: "autostart_entry_valid", pass: true, detail: "not enabled (opt-in, default off)" };
  if (status.reason === "target_missing") {
    return {
      name: "autostart_entry_valid",
      pass: false,
      detail: `${status.location} points at a file that no longer exists (${status.recorded}) — Helm will not start at login. Re-enable "Start Helm when I sign in" in the Helm tab to rewrite it with the current path.`,
    };
  }
  if (status.reason === "unreadable") {
    return { name: "autostart_entry_valid", pass: false, detail: `${status.location} exists but could not be read back — cannot confirm it still works.` };
  }
  if (status.reason === "command_mismatch") {
    return { name: "autostart_entry_valid", pass: true, detail: `points at a different Helm than the one running now (entry: ${status.recorded}; running: ${status.expected})` };
  }
  return { name: "autostart_entry_valid", pass: true, detail: status.location };
}

// `exec`/`home`/`plat` are injectable so tests never touch the real
// registry, launchd, or $HOME.
export function installAutostart({ plat = platform(), home = homedir(), exec = defaultExec, cmd = autostartCommand() } = {}) {
  if (plat === "darwin") return installMac({ home, exec, cmd });
  if (plat === "win32") return installWindows({ exec, cmd });
  return { ok: false, supported: false };
}

export function uninstallAutostart({ plat = platform(), home = homedir(), exec = defaultExec } = {}) {
  if (plat === "darwin") return uninstallMac({ home, exec });
  if (plat === "win32") return uninstallWindows({ exec });
  return { ok: false, supported: false };
}

export function isAutostartInstalled({ plat = platform(), home = homedir(), exec = defaultExec } = {}) {
  if (plat === "darwin") return isInstalledMac({ home });
  if (plat === "win32") return isInstalledWindows({ exec });
  return false;
}

// Where the autostart entry actually lives, in the exact form a user would
// need to find or audit it by hand. Installing persistence without saying
// where it went — and how to remove it — is the single behavior that makes
// an inspectable product look like an implant, so index.mjs prints this at
// the moment of install and `helmd status` reports it thereafter.
export function autostartLocation({ plat = platform(), home = homedir() } = {}) {
  if (plat === "darwin") return launchAgentPath(home);
  if (plat === "win32") return `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\${RUN_VALUE_NAME}`;
  return null;
}

function defaultExec(bin, args) {
  return execFileSync(bin, args, { stdio: "ignore" });
}

// Same call, but the caller needs what the command SAID (`reg query` output).
// Separate from defaultExec so the existing install/uninstall paths keep
// discarding output rather than buffering it.
function defaultExecOut(bin, args) {
  return execFileSync(bin, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

// Exported for tests that want to read back exactly what installMac wrote.
export { launchAgentPath, launchAgentPlist };
