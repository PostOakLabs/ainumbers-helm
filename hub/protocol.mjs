// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// helm:// custom URL-scheme registration (HELM-PROTO-BUILD-SPEC §3).
// Windows: a per-user HKCU\Software\Classes\helm key (§3.1). Linux: a
// per-user freedesktop.org .desktop entry + `xdg-mime` (§3.3). The two share
// this module's SHAPE — one status object, one consent rule — and nothing
// else: each platform's install/detection reads its own OS surface, never a
// registry-or-plist assumption borrowed across platforms. macOS needs an
// .app-bundle wrapper (§3.2, FLAG-AND-WAIT) and still reports
// `supported: false` here rather than half-working.
//
// HELM-AUTOSTART-1's consent rule binds this module too (spec §3): NOTHING in
// here may be called without an explicit user action. The only installer
// caller is the pairing tab's opt-in toggle (POST /autostart, default OFF) —
// the same tick-box event as autostart/shortcut — plus `helmd uninstall`.
// The daemon's start path never calls installProtocol (protocol.test.mjs
// asserts that against the source, the same way autostart.test.mjs does).
//
// THE THREAT MODEL (spec §2) IN ONE PARAGRAPH: the scheme is invoked by any
// website, from any tab, at any time, and every byte after `helm://` is
// attacker-controlled. Therefore the registered command is a FIXED LITERAL:
// `"<helmd.exe path>" open --from-scheme`. No `%1` placeholder, no argument
// channel, no templating from the OS-provided invocation string — Windows
// never gets to hand us a URL, because the command template has nowhere to
// put one. `--from-scheme` is a marker flag only (it lets `cmdOpen` log the
// invocation source); it carries no data and accepts none.
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir, platform } from "node:os";
import path from "node:path";

const PROTOCOL_KEY = "HKCU\\Software\\Classes\\helm";
const COMMAND_KEY = "HKCU\\Software\\Classes\\helm\\shell\\open\\command";
const PROTOCOL_DESC = "URL:AINumbers Helm Protocol";
const URL_PROTOCOL_VALUE_NAME = "URL Protocol";
// Marker flag, never an argument channel (spec §3.1) — the literal the
// registered command ends with, and the only byte not fixed by the binary path.
export const FROM_SCHEME_FLAG = "--from-scheme";

// The command the scheme registration invokes, derived the same way
// autostartCommand() derives its own — `process.execPath` for the packaged
// SEA binary (argv[1] is the binary itself), `node <entry>` for a dev
// checkout. NOTE this reads how THIS process was started, never what a
// scheme invocation carried: there is no parameter here — and no caller
// channel — for attacker-controlled input at all (spec §9 gate 1).
export function protocolCommand({ execPath = process.execPath, entry = process.argv[1] } = {}) {
  const isSea = !entry || entry === execPath;
  const args = isSea ? ["open", FROM_SCHEME_FLAG] : [entry, "open", FROM_SCHEME_FLAG];
  return { command: execPath, args };
}

function quoteWin(s) {
  return `"${s.replace(/"/g, '\\"')}"`;
}

// The executable is always quoted (spec §3.1's literal shape); the fixed
// arguments never need quotes unless a dev-checkout entry path forces one.
function quoteIfNeeded(s) {
  return /[\s"]/.test(s) ? quoteWin(s) : s;
}

// The exact (Default) string written to shell\open\command — e.g.
//   "C:\Users\me\Downloads\helmd.exe" open --from-scheme
export function protocolCommandValue(cmd = protocolCommand()) {
  return [quoteWin(cmd.command), ...cmd.args.map(quoteIfNeeded)].join(" ");
}

// Windows registration per spec §3.1, EXACTLY three values:
//   HKCU\Software\Classes\helm
//     (Default)     = "URL:AINumbers Helm Protocol"
//     URL Protocol  = ""
//   HKCU\Software\Classes\helm\shell\open\command
//     (Default)     = "\"<helmd.exe path>\" open --from-scheme"
// `exec` is injectable so tests never touch the real registry.
export function installProtocolWindows({ exec = defaultExec, cmd = protocolCommand() } = {}) {
  const value = protocolCommandValue(cmd);
  exec("reg", ["add", PROTOCOL_KEY, "/ve", "/t", "REG_SZ", "/d", PROTOCOL_DESC, "/f"]);
  exec("reg", ["add", PROTOCOL_KEY, "/v", URL_PROTOCOL_VALUE_NAME, "/t", "REG_SZ", "/d", "", "/f"]);
  exec("reg", ["add", COMMAND_KEY, "/ve", "/t", "REG_SZ", "/d", value, "/f"]);
  return { ok: true, value };
}

// Removes the whole helm key tree — scheme description, URL Protocol, and
// shell\open\command go together (spec §4: `reg delete HKCU\...\helm /f`).
export function uninstallProtocolWindows({ exec = defaultExec } = {}) {
  try {
    exec("reg", ["delete", PROTOCOL_KEY, "/f"]);
  } catch {
    // non-fatal — already removed
  }
  return { ok: true };
}

function isInstalledWindows({ exec }) {
  try {
    exec("reg", ["query", COMMAND_KEY, "/ve"]);
    return true;
  } catch {
    return false;
  }
}

// The reverse of quoteWin for the FIRST token only — the recorded value is a
// single string, and the only part of it we can check against the filesystem
// is the executable at its head (same shape as autostart.mjs).
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

function readRecordedWindows({ execOut }) {
  let out;
  try {
    out = execOut("reg", ["query", COMMAND_KEY, "/ve"]);
  } catch {
    return null; // not installed, or the hive is unreadable — same to a caller
  }
  const m = /^\s*\(Default\)\s+REG_SZ\s+(.*)$/m.exec(String(out ?? ""));
  return m ? m[1].trim() : null;
}

// ———— Linux (HELM-PROTO-3, spec §3.3) ————
// Linux's first OS-integration write in this repo: a freedesktop.org .desktop
// entry installed per-user (no admin — the same posture as the Windows HKCU
// key and every other registration here), declared as the handler for the
// helm:// scheme type and pointed at itself with `xdg-mime default`. The
// detection below reads the .desktop FILE — deliberately not the Windows
// registry parsing above, and deliberately not a plist assumption either;
// only the status SHAPE is shared (spec §3.3: "built from scratch").

const DESKTOP_FILE_NAME = "ainumbers-helm.desktop";
const HELM_SCHEME = "x-scheme-handler/helm";
const DESKTOP_ENTRY_NAME = "AINumbers Helm";

function defaultApplicationsDir() {
  return path.join(homedir(), ".local", "share", "applications");
}

// freedesktop Exec quoting: inside double quotes, backslash and double-quote
// are the only escapable bytes. The program token is ALWAYS quoted (paths
// with spaces are ordinary on Linux); the fixed arguments only when needed.
function quoteLinux(s) {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function quoteIfNeededLinux(s) {
  return /[\s"\\]/.test(s) ? quoteLinux(s) : s;
}

// The exact Exec= value written into the entry — the Linux twin of
// protocolCommandValue(): same derivation, same fixed-literal rule
// (spec §2/§9 gate 1): path + "open --from-scheme", nothing else.
export function desktopExecValue(cmd = protocolCommand()) {
  return [quoteLinux(cmd.command), ...cmd.args.map(quoteIfNeededLinux)].join(" ");
}

// And the whole entry. NOTE the Exec line carries NO % field code — the
// freedesktop launcher's mechanism for appending caller-supplied arguments
// (the Linux analogue of Windows' %1) is therefore absent entirely, so a
// scheme invocation has nowhere to inject the URL it carries (spec §2).
export function desktopEntryContent(cmd = protocolCommand()) {
  return [
    "[Desktop Entry]",
    "Type=Application",
    `Name=${DESKTOP_ENTRY_NAME}`,
    "Terminal=false",
    // Handler-only entry: it exists so desktop environments can answer a
    // helm:// click; it is not a launcher users should see in an app grid.
    // Where it lives and whether it is healthy is what protocolStatus()
    // and the doctor check report — the auditable surface is the status,
    // not a menu entry (same detectable-not-hidden discipline as §3.1).
    "NoDisplay=true",
    `Exec=${desktopExecValue(cmd)}`,
    `MimeType=${HELM_SCHEME};`,
    "",
  ].join("\n");
}

// Registration per spec §3.3: write the entry into the per-user applications
// directory, then the standard freedesktop.org call — the same shell-out
// posture as openBrowser()'s `xdg-open` (index.mjs). `desktopDir` is
// injectable so tests exercise a real file round-trip in a temp directory.
export function installProtocolLinux({ exec = defaultExec, cmd = protocolCommand(), desktopDir = defaultApplicationsDir() } = {}) {
  mkdirSync(desktopDir, { recursive: true });
  const desktopPath = path.join(desktopDir, DESKTOP_FILE_NAME);
  writeFileSync(desktopPath, desktopEntryContent(cmd));
  exec("xdg-mime", ["default", DESKTOP_FILE_NAME, HELM_SCHEME]);
  return { ok: true, value: desktopExecValue(cmd), path: desktopPath };
}

// xdg-mime has no "unset default" primitive (spec §4): deleting the entry IS
// the unregistration — a desktop environment resolves helm:// to a .desktop
// file it can no longer find and falls back to "no handler" once its caches
// catch up. KNOWN LINUX LIMITATION, documented here on purpose (spec §4):
// some desktop environments cache the association and may keep offering a
// dead handler until the cache refreshes (update-desktop-database, or a
// re-login). That is the platform behaving as designed, NOT a bug to chase —
// which is also why the best-effort cache refresh below swallows failure and
// absence (the tool need not exist) alike.
export function uninstallProtocolLinux({ exec = defaultExec, desktopDir = defaultApplicationsDir() } = {}) {
  const desktopPath = path.join(desktopDir, DESKTOP_FILE_NAME);
  try {
    rmSync(desktopPath, { force: true });
  } catch {
    // non-fatal — already removed
  }
  try {
    exec("update-desktop-database", [desktopDir]);
  } catch {
    // absent or failed — the file removal stands either way (spec §4)
  }
  return { ok: true };
}

// Reads the Exec= line back out of the installed entry. Returns null when the
// file says nothing parseable — the caller decides what that means.
function readRecordedLinux({ desktopPath, fileExists, readFile }) {
  if (!fileExists(desktopPath)) return null;
  let text;
  try {
    text = readFile(desktopPath, "utf8");
  } catch {
    return null;
  }
  const m = /^Exec=(.*)$/m.exec(String(text ?? ""));
  return m ? m[1].trim() : null;
}

// First token of an Exec= value under freedesktop quoting rules — the twin
// of firstQuotedToken() above, and deliberately separate from it: the Windows
// parser never decodes an escaped backslash (the registry never writes one),
// while this one must (quoteLinux escapes backslashes). Kept apart so neither
// platform's byte rules ever depend on the other's.
function firstLinuxExecToken(value) {
  const s = String(value).trim();
  if (!s.startsWith('"')) return s.split(/\s+/)[0] ?? "";
  let out = "";
  for (let i = 1; i < s.length; i++) {
    if (s[i] === "\\" && (s[i + 1] === '"' || s[i + 1] === "\\")) {
      out += s[i + 1];
      i++;
      continue;
    }
    if (s[i] === '"') break;
    out += s[i];
  }
  return out;
}

// Linux status, same object shape as the Windows one below (and as
// autostartStatus()): supported/installed/stale/reason/location/recorded/
// expected, with the SAME reason vocabulary — "ok" | "not_installed" |
// "unsupported" | "target_missing" | "command_mismatch" | "unreadable".
// Two Linux-specific honesty rules, both tested:
//  • target_missing — the entry's Exec points at a binary that is gone
//    (moved/renamed/deleted); stale:true, never healthy (spec §9 gate 3).
//  • command_mismatch + stale:true — the ASSOCIATION was displaced: our
//    entry is whole but `xdg-mime query` says another handler owns helm://
//    now, so clicks will NOT reach Helm at all. recorded/expected carry the
//    association pair (what owns the scheme vs what should). This is the
//    Linux squatting-detection analogue of §3.1's last-writer-wins note.
//    (command_mismatch WITHOUT stale stays the benign Windows-flavoured
//    case: the entry was rewritten under our name but points at something
//    that exists — surfaced for a human, not failed.)
function protocolStatusLinux({ exec, execOut, cmd, fileExists, readFile, desktopDir, location }) {
  const expected = desktopExecValue(cmd);
  const desktopPath = path.join(desktopDir, DESKTOP_FILE_NAME);
  if (!fileExists(desktopPath)) {
    return { supported: true, installed: false, stale: false, reason: "not_installed", location, recorded: null, expected };
  }

  const recorded = readRecordedLinux({ desktopPath, fileExists, readFile });
  if (!recorded) {
    // The entry is there but says nothing we can parse — stale, not healthy:
    // an unverifiable registration is precisely what this check exists to
    // stop reporting green (mirror of the Windows unreadable branch).
    return { supported: true, installed: true, stale: true, reason: "unreadable", location, recorded: null, expected };
  }

  const target = firstLinuxExecToken(recorded);
  if (target && !fileExists(target)) {
    return { supported: true, installed: true, stale: true, reason: "target_missing", location, recorded, expected };
  }
  if (recorded !== expected) {
    return { supported: true, installed: true, stale: false, reason: "command_mismatch", location, recorded, expected };
  }

  // The entry is ours and whole — but is it still the DEFAULT? xdg-mime
  // recorded that in ~/.config/mimeapps.list at install time, and anything
  // may have rewritten it since. `xdg-mime query` is the only honest way to
  // ask. A failed/absent query tool (headless box) leaves the question
  // unanswered: report what WAS verified — the entry — rather than inventing
  // a failure we did not observe.
  let recordedDefault = null;
  try {
    recordedDefault = String(execOut("xdg-mime", ["query", HELM_SCHEME]) ?? "").trim() || null;
  } catch {
    recordedDefault = null;
  }
  if (recordedDefault && recordedDefault !== DESKTOP_FILE_NAME) {
    return { supported: true, installed: true, stale: true, reason: "command_mismatch", location, recorded: recordedDefault, expected: DESKTOP_FILE_NAME };
  }
  return { supported: true, installed: true, stale: false, reason: "ok", location, recorded, expected };
}

// One shape for every platform, mirroring autostartStatus():
//   supported  — is scheme registration implemented here at all
//   installed  — a registration exists
//   stale      — a registration exists but cannot do its job
//   reason     — "ok" | "not_installed" | "unsupported" | "target_missing" |
//                "command_mismatch" | "unreadable"
//   recorded / expected — the two command strings, for a human to compare
//
// The staleness checks are the squatting mitigation spec §3.1 asks for:
// last-writer-wins on HKCU\Software\Classes\helm is an OS property we cannot
// close, but a stale or hijacked entry is at least DETECTABLE — never
// silently reported healthy.
export function protocolStatus({
  plat = platform(),
  exec = defaultExec,
  execOut = defaultExecOut,
  cmd = protocolCommand(),
  fileExists = existsSync,
  readFile = readFileSync,
  desktopDir = defaultApplicationsDir(),
} = {}) {
  const location = protocolLocation({ plat, desktopDir });
  if (plat === "linux") {
    return protocolStatusLinux({ exec, execOut, cmd, fileExists, readFile, desktopDir, location });
  }
  if (plat !== "win32") {
    return { supported: false, installed: false, stale: false, reason: "unsupported", location, recorded: null, expected: null };
  }

  const expected = protocolCommandValue(cmd);
  const installed = isInstalledWindows({ exec });
  if (!installed) {
    return { supported: true, installed: false, stale: false, reason: "not_installed", location, recorded: null, expected };
  }

  const recorded = readRecordedWindows({ execOut });
  if (!recorded) {
    // The key is there but we cannot read what it says — treat as stale
    // rather than healthy: an unverifiable registration is precisely the
    // thing this check exists to stop reporting green.
    return { supported: true, installed: true, stale: true, reason: "unreadable", location, recorded: null, expected };
  }

  const target = firstQuotedToken(recorded);
  if (target && !fileExists(target)) {
    return { supported: true, installed: true, stale: true, reason: "target_missing", location, recorded, expected };
  }
  if (recorded !== expected) {
    // The target exists but is not the helmd that is running now — a second
    // copy of the binary, or another app's registration. Worth showing; NOT a
    // failure, since the recorded entry would still launch a working Helm.
    return { supported: true, installed: true, stale: false, reason: "command_mismatch", location, recorded, expected };
  }
  return { supported: true, installed: true, stale: false, reason: "ok", location, recorded, expected };
}

// Lives here, not in doctor.mjs, for the same reason autostartDoctorCheck
// does: its injectables (fake registry) are reachable from a test without
// doctor.mjs growing an injection seam for the whole self-check.
export function protocolDoctorCheck(opts = {}) {
  const status = protocolStatus(opts);
  if (!status.supported) return { name: "protocol_handler_valid", pass: true, detail: "not supported on this platform" };
  if (!status.installed) return { name: "protocol_handler_valid", pass: true, detail: "not registered (opt-in, default off)" };
  if (status.reason === "target_missing") {
    return {
      name: "protocol_handler_valid",
      pass: false,
      detail: `${status.location} points at a file that no longer exists (${status.recorded}) — helm:// links will fail. Re-enable "Open helm:// links with Helm" in the Helm tab to rewrite it with the current path.`,
    };
  }
  if (status.reason === "unreadable") {
    return { name: "protocol_handler_valid", pass: false, detail: `${status.location} exists but could not be read back — cannot confirm helm:// links still work.` };
  }
  if (status.reason === "command_mismatch") {
    // stale + command_mismatch is the Linux displaced-association shape:
    // another handler owns helm:// now, so links do not reach Helm at all —
    // a FAIL, never a quiet pass (spec §3.4: a stale registration must never
    // silently report healthy). Without stale it stays the benign "different
    // but working Helm" case the Windows branch below has always meant.
    if (status.stale) {
      return {
        name: "protocol_handler_valid",
        pass: false,
        detail: `another handler is the default for helm:// links (${status.recorded}) — helm:// clicks will not open Helm. Re-enable "Open helm:// links with Helm" in the Helm tab to reclaim them.`,
      };
    }
    return { name: "protocol_handler_valid", pass: true, detail: `points at a different Helm than the one running now (registered: ${status.recorded}; running: ${status.expected})` };
  }
  return { name: "protocol_handler_valid", pass: true, detail: status.location };
}

// `exec` is injectable so tests never touch the real registry; the
// plat-dispatch wrappers mirror autostart.mjs's installAutostart shape.
export function installProtocol({ plat = platform(), exec = defaultExec, cmd = protocolCommand(), desktopDir = defaultApplicationsDir() } = {}) {
  if (plat === "win32") return installProtocolWindows({ exec, cmd });
  if (plat === "linux") return installProtocolLinux({ exec, cmd, desktopDir });
  return { ok: false, supported: false };
}

export function uninstallProtocol({ plat = platform(), exec = defaultExec, desktopDir = defaultApplicationsDir() } = {}) {
  if (plat === "win32") return uninstallProtocolWindows({ exec });
  if (plat === "linux") return uninstallProtocolLinux({ exec, desktopDir });
  return { ok: false, supported: false };
}

export function isProtocolInstalled({ plat = platform(), exec = defaultExec, desktopDir = defaultApplicationsDir(), fileExists = existsSync } = {}) {
  if (plat === "win32") return isInstalledWindows({ exec });
  if (plat === "linux") return fileExists(path.join(desktopDir, DESKTOP_FILE_NAME));
  return false;
}

// Where the registration actually lives, in the exact form a user would need
// to find or audit it by hand — same discipline as autostartLocation().
export function protocolLocation({ plat = platform(), desktopDir = defaultApplicationsDir() } = {}) {
  if (plat === "win32") return COMMAND_KEY;
  if (plat === "linux") return path.join(desktopDir, DESKTOP_FILE_NAME);
  return null;
}

function defaultExec(bin, args) {
  return execFileSync(bin, args, { stdio: "ignore" });
}

// Same call, but the caller needs what the command SAID (`reg query` output).
function defaultExecOut(bin, args) {
  return execFileSync(bin, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

// Exported so tests (and the status payload) can assert/report the exact
// registered key paths and values against spec §3.1 / §3.3.
export { PROTOCOL_KEY, COMMAND_KEY, PROTOCOL_DESC, URL_PROTOCOL_VALUE_NAME, DESKTOP_FILE_NAME, HELM_SCHEME };
