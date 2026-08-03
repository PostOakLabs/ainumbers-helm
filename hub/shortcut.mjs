// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Start Menu shortcut. The reported failure was "I ran the installer and
// nothing happened": winget's `portable` installer type drops the binary and
// adds a PATH alias, and that is ALL it can do — the portable type cannot
// create a Start Menu entry or a desktop shortcut at any manifest setting.
// So a successful `winget install AINumbers.Helm` left the user with nothing
// to click and no visible sign anything had been installed.
//
// Rather than move to an MSI/NSIS installer (a large lift that wants the code
// signing story settled first), helmd creates its own shortcut — per-user,
// removed by `helmd uninstall`. That also means npm and raw-binary installs
// get the shortcut too, which a winget-only packaging fix would not have done.
//
// HELM-AUTOSTART-1: this used to happen on first run, unconditionally, in the
// same breath as the autostart entry. Both are opt-in now (POST /autostart),
// for the reason written up at the top of autostart.mjs — a console
// announcement is not consent when the console is already closed. A shortcut
// is a far milder write than a Run key, but it went in through the same
// unasked-for first-run path, so it leaves by the same door.
//
// The shortcut targets the BINARY, never a URL. A .lnk or .url carrying the
// pairing link would write a long-lived bearer token to an unprotected file
// and reuse one token across every launch, defeating the address-bar scrub in
// ui/api.mjs. Launch the daemon and let it mint a fresh link.
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { homedir, platform } from "node:os";
import { join, dirname } from "node:path";
import { autostartCommand } from "./autostart.mjs";

const SHORTCUT_FILENAME = "Helm.lnk";

function startMenuDir(home) {
  return join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs");
}

function shortcutPathWindows(home) {
  return join(startMenuDir(home), SHORTCUT_FILENAME);
}

// Single-quoted PowerShell literals: no expansion of $, backtick or quotes,
// and the only escape needed is doubling an embedded apostrophe. Paths under
// C:\Users\<name> can legitimately contain one.
function psLiteral(s) {
  return `'${String(s).replace(/'/g, "''")}'`;
}

function installWindows({ home, exec, cmd }) {
  const dir = startMenuDir(home);
  mkdirSync(dir, { recursive: true });
  const path = shortcutPathWindows(home);
  // A .lnk is a COM-authored binary format; WScript.Shell is the only way to
  // write one without a native dependency, and vault.mjs already establishes
  // the PowerShell shell-out pattern for exactly this reason. One-time, on
  // first run only.
  const script = [
    "$ErrorActionPreference='Stop'",
    `$s=(New-Object -ComObject WScript.Shell).CreateShortcut(${psLiteral(path)})`,
    `$s.TargetPath=${psLiteral(cmd.command)}`,
    `$s.Arguments=${psLiteral(cmd.args.join(" "))}`,
    `$s.WorkingDirectory=${psLiteral(dirname(cmd.command))}`,
    "$s.Description='AINumbers Helm - local control plane'",
    "$s.Save()",
  ].join("; ");
  exec("powershell", ["-NoProfile", "-NonInteractive", "-Command", script]);
  return { ok: true, path };
}

function uninstallWindows({ home }) {
  const path = shortcutPathWindows(home);
  if (existsSync(path)) unlinkSync(path);
  return { ok: true, path };
}

function isInstalledWindows({ home }) {
  return existsSync(shortcutPathWindows(home));
}

// `exec`/`home`/`plat` are injectable so tests never write into a real Start
// Menu or spawn a real PowerShell.
//
// HELM-WINSPAM-1: `cmd` defaults to `autostartCommand({ open: true })`, NOT
// the bare `autostartCommand()` the autostart entry uses — a double-click on
// this shortcut IS the explicit user action the pairing tab exists for, and
// with index.mjs no longer auto-opening on every start, this is now the only
// thing that makes that click show the daemon's tab.
export function installShortcut({ plat = platform(), home = homedir(), exec = defaultExec, cmd = autostartCommand({ open: true }) } = {}) {
  if (plat === "win32") return installWindows({ home, exec, cmd });
  // macOS wants a .app bundle and Linux a .desktop entry; neither is written
  // yet, and reporting `supported: false` is honest where a silent no-op
  // would leave the caller announcing a shortcut that does not exist.
  return { ok: false, supported: false };
}

export function uninstallShortcut({ plat = platform(), home = homedir() } = {}) {
  if (plat === "win32") return uninstallWindows({ home });
  return { ok: false, supported: false };
}

export function isShortcutInstalled({ plat = platform(), home = homedir() } = {}) {
  if (plat === "win32") return isInstalledWindows({ home });
  return false;
}

// Where the shortcut lives, for the first-run announcement and `helmd status`
// — same reasoning as autostartLocation(): anything this installs on a user's
// machine, the user gets told about, in a form they can go and look at.
export function shortcutLocation({ plat = platform(), home = homedir() } = {}) {
  if (plat === "win32") return shortcutPathWindows(home);
  return null;
}

function defaultExec(bin, args) {
  return execFileSync(bin, args, { stdio: "ignore" });
}

export { shortcutPathWindows };
