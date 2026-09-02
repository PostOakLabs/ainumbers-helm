// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// helm:// custom URL-scheme registration (HELM-PROTO-BUILD-SPEC §3.1).
// Windows-only in this row — a per-user HKCU\Software\Classes\helm key, the
// same no-admin posture as autostart.mjs's HKCU Run value and shortcut.mjs's
// Start Menu .lnk. macOS needs an .app-bundle wrapper (spec §3.2, FLAG-AND-
// WAIT) and Linux a .desktop writer (spec §3.3, a later WU); both report
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
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { platform } from "node:os";

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
} = {}) {
  const location = protocolLocation({ plat });
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
    return { name: "protocol_handler_valid", pass: true, detail: `points at a different Helm than the one running now (registered: ${status.recorded}; running: ${status.expected})` };
  }
  return { name: "protocol_handler_valid", pass: true, detail: status.location };
}

// `exec` is injectable so tests never touch the real registry; the
// plat-dispatch wrappers mirror autostart.mjs's installAutostart shape.
export function installProtocol({ plat = platform(), exec = defaultExec, cmd = protocolCommand() } = {}) {
  if (plat === "win32") return installProtocolWindows({ exec, cmd });
  return { ok: false, supported: false };
}

export function uninstallProtocol({ plat = platform(), exec = defaultExec } = {}) {
  if (plat === "win32") return uninstallProtocolWindows({ exec });
  return { ok: false, supported: false };
}

export function isProtocolInstalled({ plat = platform(), exec = defaultExec } = {}) {
  if (plat === "win32") return isInstalledWindows({ exec });
  return false;
}

// Where the registration actually lives, in the exact form a user would need
// to find or audit it by hand — same discipline as autostartLocation().
export function protocolLocation({ plat = platform() } = {}) {
  if (plat === "win32") return COMMAND_KEY;
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
// registered key paths and values against spec §3.1.
export { PROTOCOL_KEY, COMMAND_KEY, PROTOCOL_DESC, URL_PROTOCOL_VALUE_NAME };
