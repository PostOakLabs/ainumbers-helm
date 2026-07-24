// Autostart (HELM-P4-J4): the last CLI moment. First run writes a per-user
// launcher so helmd survives reboots without a terminal ever reopening —
// macOS gets a LaunchAgent (RunAtLoad + KeepAlive = crash self-heal, visible
// in System Settings > Login Items), Windows gets an HKCU Run value. Both
// are per-user (no admin), and both are removed on uninstall (Zoom-orphan
// lesson, P3 robustness #8 — a leftover autostart entry after uninstall is
// the failure mode we're avoiding). Linux has no single-user autostart
// convention worth committing to yet — no-op, `supported: false`.
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs";
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
  <true/>
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

function installWindows({ exec, cmd }) {
  const value = [cmd.command, ...cmd.args].map(quoteWin).join(" ");
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

function defaultExec(bin, args) {
  return execFileSync(bin, args, { stdio: "ignore" });
}

// Exported for tests that want to read back exactly what installMac wrote.
export { launchAgentPath, launchAgentPlist };
