import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  installAutostart,
  uninstallAutostart,
  isAutostartInstalled,
  autostartCommand,
  autostartStatus,
  autostartDoctorCheck,
  parsePlistProgramArguments,
  launchAgentPath,
  launchAgentPlist,
} from "./autostart.mjs";

const cmd = { command: "/usr/local/bin/helmd", args: ["start"] };

test("autostartCommand: SEA binary invocation (argv[1] === execPath)", () => {
  const r = autostartCommand({ execPath: "/usr/local/bin/helmd", entry: "/usr/local/bin/helmd" });
  assert.deepEqual(r, { command: "/usr/local/bin/helmd", args: ["start"] });
});

test("autostartCommand: dev checkout invocation (node + script path)", () => {
  const r = autostartCommand({ execPath: "/usr/bin/node", entry: "/repo/hub/index.mjs" });
  assert.deepEqual(r, { command: "/usr/bin/node", args: ["/repo/hub/index.mjs", "start"] });
});

test("macOS: install writes a LaunchAgent plist with RunAtLoad true and KeepAlive FALSE", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-autostart-mac-"));
  const calls = [];
  const exec = (bin, args) => calls.push([bin, args]);
  try {
    const result = installAutostart({ plat: "darwin", home, exec, cmd });
    assert.equal(result.ok, true);
    assert.equal(isAutostartInstalled({ plat: "darwin", home }), true);

    const plist = readFileSync(launchAgentPath(home), "utf8");
    assert.match(plist, /<key>RunAtLoad<\/key>\s*<true\/>/);
    // KeepAlive MUST stay false. With it true, launchd relaunches helmd the
    // instant it exits, which made `helmd stop`, a UI Quit button and plain
    // kill(1) all lies on macOS — the user had no off switch short of
    // `helmd uninstall`. RunAtLoad alone gives start-on-login, which is the
    // actual goal. Do not "restore" this for crash self-heal.
    assert.match(plist, /<key>KeepAlive<\/key>\s*<false\/>/);
    assert.match(plist, /<string>\/usr\/local\/bin\/helmd<\/string>/);
    assert.match(plist, /<string>start<\/string>/);
    assert.equal(plist, launchAgentPlist(cmd));

    // best-effort launchctl load was attempted
    assert.deepEqual(calls[0], ["launchctl", ["load", launchAgentPath(home)]]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("macOS: install is non-fatal when launchctl itself fails (headless/CI)", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-autostart-mac-"));
  const exec = () => {
    throw new Error("no launchd session");
  };
  try {
    const result = installAutostart({ plat: "darwin", home, exec, cmd });
    assert.equal(result.ok, true);
    assert.equal(existsSync(launchAgentPath(home)), true);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// Round-trip: install → (reboot-sim: state persists on disk, nothing re-runs
// install) → uninstall → gone. The "reboot" is simulated by simply reading
// the file back rather than re-invoking install, since RunAtLoad's actual
// re-launch behavior belongs to the OS, not this module.
test("macOS: install -> reboot-sim (still present) -> uninstall -> gone", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-autostart-mac-"));
  const exec = () => {};
  try {
    installAutostart({ plat: "darwin", home, exec, cmd });
    assert.equal(isAutostartInstalled({ plat: "darwin", home }), true, "present after install");
    assert.equal(isAutostartInstalled({ plat: "darwin", home }), true, "still present after reboot-sim re-check");

    const uninstallResult = uninstallAutostart({ plat: "darwin", home, exec });
    assert.equal(uninstallResult.ok, true);
    assert.equal(isAutostartInstalled({ plat: "darwin", home }), false, "gone after uninstall");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("macOS: uninstall is idempotent when nothing was ever installed", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-autostart-mac-"));
  const exec = () => {
    throw new Error("not loaded");
  };
  try {
    const result = uninstallAutostart({ plat: "darwin", home, exec });
    assert.equal(result.ok, true);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// Windows: no real registry access — exec is fully mocked and its call args
// are asserted directly. A fake in-memory "registry" simulates query/add/
// delete so isAutostartInstalled's round-trip is meaningful, not just a
// call-shape assertion.
function fakeWindowsRegistry() {
  let installed = false;
  const calls = [];
  const exec = (bin, args) => {
    calls.push([bin, args]);
    if (bin !== "reg") throw new Error(`unexpected binary ${bin}`);
    if (args[0] === "add") {
      installed = true;
      return;
    }
    if (args[0] === "delete") {
      if (!installed) throw new Error("value not found");
      installed = false;
      return;
    }
    if (args[0] === "query") {
      if (!installed) throw new Error("value not found");
      return;
    }
    throw new Error(`unexpected reg subcommand ${args[0]}`);
  };
  return { exec, calls, isInstalled: () => installed };
}

test("Windows: install writes an HKCU Run value, uninstall removes it", () => {
  const reg = fakeWindowsRegistry();
  assert.equal(isAutostartInstalled({ plat: "win32", exec: reg.exec }), false);

  const installResult = installAutostart({ plat: "win32", exec: reg.exec, cmd });
  assert.equal(installResult.ok, true);
  assert.equal(isAutostartInstalled({ plat: "win32", exec: reg.exec }), true);

  const addCall = reg.calls.find((c) => c[1][0] === "add");
  assert.ok(addCall, "reg add was called");
  assert.match(addCall[1].join(" "), /CurrentVersion\\Run/);
  assert.match(addCall[1].join(" "), /AINumbersHelmd/);
  assert.match(addCall[1].join(" "), /helmd start|helmd" "start/);

  // reboot-sim: state persists in the fake registry across a second check
  assert.equal(isAutostartInstalled({ plat: "win32", exec: reg.exec }), true);

  const uninstallResult = uninstallAutostart({ plat: "win32", exec: reg.exec });
  assert.equal(uninstallResult.ok, true);
  assert.equal(isAutostartInstalled({ plat: "win32", exec: reg.exec }), false, "gone after uninstall");
});

test("Windows: uninstall is non-fatal when the value never existed", () => {
  const reg = fakeWindowsRegistry();
  const result = uninstallAutostart({ plat: "win32", exec: reg.exec });
  assert.equal(result.ok, true);
});

// HELM-AUTOSTART-1 §3.1, the regression that matters most: the daemon's own
// start path must contain NO installer call at all. Asserted against the
// source rather than by booting a first-run daemon, because the only honest
// way to test the boot version is to let it write to the real registry of
// whatever machine runs the suite — which is the exact act being forbidden.
//
// If a future change genuinely needs helmd to install autostart itself, this
// test is the place that argument has to be won.
test("index.mjs: no start path calls an autostart or shortcut installer", () => {
  const source = readFileSync(new URL("./index.mjs", import.meta.url), "utf8");
  // Strip comments — this file explains at length WHY the installs were
  // removed, and those explanations name the functions.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  // \b so "uninstallAutostart" — which contains "installAutostart" — doesn't
  // trip this. The uninstall path is allowed; the install path is not.
  assert.doesNotMatch(code, /\binstallAutostart/, "helmd must never install autostart without an explicit user action");
  assert.doesNotMatch(code, /\binstallShortcut/, "helmd must never install a shortcut without an explicit user action");
  // uninstall stays: `helmd uninstall` is itself an explicit user action.
  assert.match(code, /uninstallAutostart/);
});

// --- HELM-AUTOSTART-1 §4: an entry that exists but no longer works ---
//
// The shipped isInstalled* pair answered "does the value/plist exist", which
// is not the same question as "will this actually start Helm". Move or rename
// the binary and the Run key survives pointing at nothing: Explorer fails
// silently at every logon while `helmd status` and the UI both report healthy.
// That is the state these tests refuse to let pass.

// Extends the fake above with a readable value, so autostartStatus's
// `reg query` output parsing is exercised against the real output shape
// rather than a hand-fed string.
function fakeWindowsRegistryWithValue(initialValue = null) {
  let value = initialValue;
  const exec = (bin, args) => {
    if (bin !== "reg") throw new Error(`unexpected binary ${bin}`);
    if (args[0] === "add") {
      value = args[args.indexOf("/d") + 1];
      return;
    }
    if (args[0] === "delete") {
      if (value === null) throw new Error("value not found");
      value = null;
      return;
    }
    if (args[0] === "query") {
      if (value === null) throw new Error("value not found");
      return;
    }
    throw new Error(`unexpected reg subcommand ${args[0]}`);
  };
  const execOut = (bin, args) => {
    exec(bin, args);
    // Real `reg query` output shape, tabs and all.
    return `\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    AINumbersHelmd    REG_SZ    ${value}\r\n\r\n`;
  };
  return { exec, execOut, current: () => value };
}

test("status (Windows): a Run value whose target no longer exists is STALE, not healthy", () => {
  const reg = fakeWindowsRegistryWithValue();
  const cmd = { command: "C:\\Users\\x\\Downloads\\helmd (2).exe", args: ["start"] };
  installAutostart({ plat: "win32", exec: reg.exec, cmd });

  // isAutostartInstalled — the pre-fix instrument — still says "yes, fine".
  assert.equal(isAutostartInstalled({ plat: "win32", exec: reg.exec }), true);

  const status = autostartStatus({
    plat: "win32",
    exec: reg.exec,
    execOut: reg.execOut,
    cmd,
    fileExists: () => false, // the user moved/renamed/deleted the exe
  });
  assert.equal(status.installed, true);
  assert.equal(status.stale, true, "an entry pointing at a missing file must never report healthy");
  assert.equal(status.reason, "target_missing");
  assert.match(status.recorded, /Downloads/);
});

test("status (Windows): recorded value matching the running command is ok, not stale", () => {
  const reg = fakeWindowsRegistryWithValue();
  const cmd = { command: "C:\\Program Files\\Helm\\helmd.exe", args: ["start"] };
  installAutostart({ plat: "win32", exec: reg.exec, cmd });

  const status = autostartStatus({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => true });
  assert.equal(status.stale, false);
  assert.equal(status.reason, "ok");
  assert.equal(status.installed, true);
});

test("status (Windows): a value pointing at a DIFFERENT but existing helmd is surfaced, not treated as broken", () => {
  const reg = fakeWindowsRegistryWithValue();
  installAutostart({ plat: "win32", exec: reg.exec, cmd: { command: "C:\\old\\helmd.exe", args: ["start"] } });

  const status = autostartStatus({
    plat: "win32",
    exec: reg.exec,
    execOut: reg.execOut,
    cmd: { command: "C:\\new\\helmd.exe", args: ["start"] },
    fileExists: () => true,
  });
  assert.equal(status.reason, "command_mismatch");
  // Not stale: that entry would still start a working Helm at logon.
  assert.equal(status.stale, false);
});

test("status (Windows): nothing installed reports not_installed, never stale", () => {
  const reg = fakeWindowsRegistryWithValue();
  const status = autostartStatus({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => true });
  assert.equal(status.installed, false);
  assert.equal(status.stale, false);
  assert.equal(status.reason, "not_installed");
});

test("status (macOS): a LaunchAgent whose ProgramArguments target is gone is STALE", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-autostart-mac-"));
  try {
    installAutostart({ plat: "darwin", home, exec: () => {}, cmd });
    assert.equal(isAutostartInstalled({ plat: "darwin", home }), true);

    const status = autostartStatus({ plat: "darwin", home, exec: () => {}, cmd, fileExists: () => false });
    assert.equal(status.stale, true);
    assert.equal(status.reason, "target_missing");

    const healthy = autostartStatus({ plat: "darwin", home, exec: () => {}, cmd, fileExists: () => true });
    assert.equal(healthy.reason, "ok");
    assert.equal(healthy.stale, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("parsePlistProgramArguments: round-trips what launchAgentPlist wrote, entity-decoded", () => {
  const odd = { command: "/Apps/He<l>m & co/helmd", args: ["start"] };
  assert.deepEqual(parsePlistProgramArguments(launchAgentPlist(odd)), ["/Apps/He<l>m & co/helmd", "start"]);
  assert.equal(parsePlistProgramArguments("<plist></plist>"), null);
});

test("doctor check: FAILS on a stale entry, PASSES when autostart is simply off", () => {
  const reg = fakeWindowsRegistryWithValue();

  // Off by default (HELM-AUTOSTART-1) — that is a healthy machine, not a fault.
  const off = autostartDoctorCheck({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => true });
  assert.equal(off.name, "autostart_entry_valid");
  assert.equal(off.pass, true);

  installAutostart({ plat: "win32", exec: reg.exec, cmd });
  const broken = autostartDoctorCheck({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => false });
  assert.equal(broken.pass, false, "doctor must report a dead autostart entry instead of reporting healthy");
  assert.match(broken.detail, /no longer exists/);
});

test("doctor check: an unreadable entry is a FAIL, not an assumed-healthy one", () => {
  const status = autostartDoctorCheck({
    plat: "win32",
    exec: () => {}, // query succeeds -> "installed"
    execOut: () => "HKEY_CURRENT_USER\\...\\Run\r\n    SomethingElse    REG_SZ    x\r\n",
    cmd,
    fileExists: () => true,
  });
  assert.equal(status.pass, false);
  assert.match(status.detail, /could not be read back/);
});

test("unsupported platform (linux): reports unsupported, never throws", () => {
  assert.deepEqual(installAutostart({ plat: "linux", exec: () => {}, cmd }), { ok: false, supported: false });
  assert.deepEqual(uninstallAutostart({ plat: "linux", exec: () => {} }), { ok: false, supported: false });
  assert.equal(isAutostartInstalled({ plat: "linux", exec: () => {} }), false);

  const status = autostartStatus({ plat: "linux", exec: () => {}, execOut: () => "", cmd });
  assert.equal(status.supported, false);
  assert.equal(status.stale, false);
  assert.equal(status.reason, "unsupported");
  assert.equal(autostartDoctorCheck({ plat: "linux", exec: () => {}, execOut: () => "", cmd }).pass, true);
});
