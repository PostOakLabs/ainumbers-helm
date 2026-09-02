import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  installProtocol,
  uninstallProtocol,
  installProtocolWindows,
  uninstallProtocolWindows,
  installProtocolLinux,
  uninstallProtocolLinux,
  isProtocolInstalled,
  protocolCommand,
  protocolCommandValue,
  desktopExecValue,
  desktopEntryContent,
  protocolStatus,
  protocolDoctorCheck,
  protocolLocation,
  PROTOCOL_KEY,
  COMMAND_KEY,
  PROTOCOL_DESC,
  FROM_SCHEME_FLAG,
  DESKTOP_FILE_NAME,
  HELM_SCHEME,
} from "./protocol.mjs";

const cmd = { command: "C:\\Users\\me\\Downloads\\helmd.exe", args: ["open", FROM_SCHEME_FLAG] };
const linuxCmd = { command: "/opt/helm/bin/helmd", args: ["open", FROM_SCHEME_FLAG] };

test("protocolCommand: SEA binary invocation (argv[1] === execPath)", () => {
  const r = protocolCommand({ execPath: "C:\\apps\\helmd.exe", entry: "C:\\apps\\helmd.exe" });
  assert.deepEqual(r, { command: "C:\\apps\\helmd.exe", args: ["open", FROM_SCHEME_FLAG] });
});

test("protocolCommand: dev checkout invocation (node + script path)", () => {
  const r = protocolCommand({ execPath: "C:\\node.exe", entry: "C:\\repo\\hub\\index.mjs" });
  assert.deepEqual(r, { command: "C:\\node.exe", args: ["C:\\repo\\hub\\index.mjs", "open", FROM_SCHEME_FLAG] });
});

// HELM-PROTO-BUILD-SPEC §9 gate 1 — the regression that matters most. The
// scheme is invoked by any website from any tab (spec §2), so every byte of
// the registered command beyond the binary path must be a fixed literal: no
// %1 placeholder, no templating from the OS-provided invocation string, no
// argument channel. The command-construction surface takes NOTHING that could
// carry one — these assertions pin the literal so a future "helpful" change
// (passing the URL through, accepting a target verb) cannot land silently.
test("gate 1: the registered command line is a fixed literal — path + 'open --from-scheme', nothing else", () => {
  const value = protocolCommandValue(cmd);
  assert.equal(value, '"C:\\Users\\me\\Downloads\\helmd.exe" open --from-scheme');
  assert.match(value, /^"[^"]*" open --from-scheme$/, "exactly one templated byte sequence allowed: the binary path");

  const sea = protocolCommand({ execPath: "C:\\apps\\helmd.exe", entry: "C:\\apps\\helmd.exe" });
  assert.deepEqual(sea.args, ["open", FROM_SCHEME_FLAG], "no verb/argument beyond the fixed pair, from any input");
});

test("installProtocolWindows: writes the §3.1 keys EXACTLY — description, URL Protocol, fixed-literal command", () => {
  const calls = [];
  const exec = (bin, args) => calls.push([bin, args]);

  const result = installProtocolWindows({ exec, cmd });
  assert.equal(result.ok, true);
  assert.equal(calls.length, 3, "exactly three reg writes: (Default), URL Protocol, shell\\open\\command");
  for (const [bin] of calls) assert.equal(bin, "reg");
  for (const [, args] of calls) assert.equal(args[0], "add");

  const [desc, urlProtocol, command] = calls.map(([, args]) => args);

  // HKCU\Software\Classes\helm (Default) = "URL:AINumbers Helm Protocol"
  assert.equal(desc[1], PROTOCOL_KEY);
  assert.deepEqual(desc.slice(2), ["/ve", "/t", "REG_SZ", "/d", PROTOCOL_DESC, "/f"]);
  assert.equal(PROTOCOL_DESC, "URL:AINumbers Helm Protocol");

  // HKCU\Software\Classes\helm URL Protocol = ""
  assert.equal(urlProtocol[1], PROTOCOL_KEY);
  assert.deepEqual(urlProtocol.slice(2), ["/v", "URL Protocol", "/t", "REG_SZ", "/d", "", "/f"]);

  // HKCU\Software\Classes\helm\shell\open\command (Default) = the fixed literal
  assert.equal(command[1], COMMAND_KEY);
  assert.equal(protocolLocation({ plat: "win32" }), COMMAND_KEY);
  assert.deepEqual(command.slice(2), ["/ve", "/t", "REG_SZ", "/d", protocolCommandValue(cmd), "/f"]);
});

// Windows: no real registry access — exec is fully mocked and its call args
// are asserted directly (same approach as autostart.test.mjs). A fake
// in-memory "registry" simulates add/query/delete so the round-trips are
// meaningful, and execOut returns the REAL `reg query` output shape.
function fakeWindowsRegistry() {
  const state = { desc: null, urlProtocol: null, command: null };
  const calls = [];
  const exec = (bin, args) => {
    calls.push([bin, args]);
    if (bin !== "reg") throw new Error(`unexpected binary ${bin}`);
    if (args[0] === "add") {
      const key = args[1];
      const data = args[args.indexOf("/d") + 1];
      if (key === PROTOCOL_KEY) {
        if (args[2] === "/ve") state.desc = data;
        else state.urlProtocol = data;
      } else if (key === COMMAND_KEY) {
        state.command = data;
      } else {
        throw new Error(`unexpected key ${key}`);
      }
      return;
    }
    if (args[0] === "delete") {
      if (args[1] !== PROTOCOL_KEY) throw new Error(`unexpected key ${args[1]}`);
      if (state.desc === null && state.urlProtocol === null && state.command === null) throw new Error("key not found");
      state.desc = state.urlProtocol = state.command = null;
      return;
    }
    if (args[0] === "query") {
      const key = args[1];
      if (key === COMMAND_KEY) {
        if (state.command === null) throw new Error("key not found");
        return;
      }
      throw new Error(`unexpected key ${key}`);
    }
    throw new Error(`unexpected reg subcommand ${args[0]}`);
  };
  const execOut = (bin, args) => {
    exec(bin, args);
    // Real `reg query ...\shell\open\command /ve` output shape, tabs and all.
    return `\r\nHKEY_CURRENT_USER\\Software\\Classes\\helm\\shell\\open\\command\r\n    (Default)    REG_SZ    ${state.command}\r\n\r\n`;
  };
  return { exec, execOut, calls, state };
}

test("Windows: install registers the scheme, uninstall removes it completely", () => {
  const reg = fakeWindowsRegistry();
  assert.equal(isProtocolInstalled({ plat: "win32", exec: reg.exec }), false);

  const result = installProtocol({ plat: "win32", exec: reg.exec, cmd });
  assert.equal(result.ok, true);
  assert.equal(isProtocolInstalled({ plat: "win32", exec: reg.exec }), true, "present after install");
  assert.equal(isProtocolInstalled({ plat: "win32", exec: reg.exec }), true, "still present after reboot-sim re-check");

  // uninstallProtocolWindows deletes the WHOLE helm key tree (spec §4), so a
  // residual registration of any of the three values is the failure mode.
  const uninstallResult = uninstallProtocol({ plat: "win32", exec: reg.exec });
  assert.equal(uninstallResult.ok, true);
  assert.equal(isProtocolInstalled({ plat: "win32", exec: reg.exec }), false, "gone after uninstall");
  assert.deepEqual(reg.state, { desc: null, urlProtocol: null, command: null }, "no residual registration");
  const deletes = reg.calls.filter(([bin, args]) => bin === "reg" && args[0] === "delete");
  assert.deepEqual(deletes, [["reg", ["delete", PROTOCOL_KEY, "/f"]]], "one tree delete, per spec §4");
});

test("Windows: uninstall is non-fatal when the key never existed", () => {
  const reg = fakeWindowsRegistry();
  const result = uninstallProtocolWindows({ exec: reg.exec });
  assert.equal(result.ok, true);
});

test("status (Windows): recorded value matching the running command is ok, not stale", () => {
  const reg = fakeWindowsRegistry();
  installProtocol({ plat: "win32", exec: reg.exec, cmd });

  const status = protocolStatus({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => true });
  assert.equal(status.supported, true);
  assert.equal(status.installed, true);
  assert.equal(status.stale, false);
  assert.equal(status.reason, "ok");
  assert.equal(status.recorded, protocolCommandValue(cmd));
  assert.equal(status.expected, protocolCommandValue(cmd));
});

test("status (Windows): a registration whose target no longer exists is STALE, not healthy", () => {
  const reg = fakeWindowsRegistry();
  installProtocol({ plat: "win32", exec: reg.exec, cmd });

  // isProtocolInstalled — the existence-only instrument — still says "yes".
  assert.equal(isProtocolInstalled({ plat: "win32", exec: reg.exec }), true);

  const status = protocolStatus({
    plat: "win32",
    exec: reg.exec,
    execOut: reg.execOut,
    cmd,
    fileExists: () => false, // the user moved/renamed/deleted the exe
  });
  assert.equal(status.installed, true);
  assert.equal(status.stale, true, "a registration pointing at a missing file must never report healthy");
  assert.equal(status.reason, "target_missing");
  assert.match(status.recorded, /Downloads/);
});

test("status (Windows): a registration pointing at a DIFFERENT but existing helmd is surfaced, not treated as broken", () => {
  const reg = fakeWindowsRegistry();
  installProtocol({ plat: "win32", exec: reg.exec, cmd: { command: "C:\\old\\helmd.exe", args: ["open", FROM_SCHEME_FLAG] } });

  const status = protocolStatus({
    plat: "win32",
    exec: reg.exec,
    execOut: reg.execOut,
    cmd: { command: "C:\\new\\helmd.exe", args: ["open", FROM_SCHEME_FLAG] },
    fileExists: () => true,
  });
  assert.equal(status.reason, "command_mismatch");
  // Not stale: that entry would still launch a working Helm.
  assert.equal(status.stale, false);
});

test("status (Windows): nothing installed reports not_installed, never stale", () => {
  const reg = fakeWindowsRegistry();
  const status = protocolStatus({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => true });
  assert.equal(status.installed, false);
  assert.equal(status.stale, false);
  assert.equal(status.reason, "not_installed");
  assert.equal(status.recorded, null);
  assert.equal(status.expected, protocolCommandValue(cmd));
});

test("status (Windows): a key we cannot read back is stale/unreadable, never healthy", () => {
  const reg = fakeWindowsRegistry();
  // Install a command value, then make `reg query` answer with a DIFFERENT
  // value name — the key exists but says nothing we can parse.
  installProtocol({ plat: "win32", exec: reg.exec, cmd });
  const brokenExecOut = (bin, args) => {
    reg.exec(bin, args);
    return "\r\nHKEY_CURRENT_USER\\Software\\Classes\\helm\\shell\\open\\command\r\n    SomethingElse    REG_SZ    x\r\n\r\n";
  };
  const status = protocolStatus({ plat: "win32", exec: reg.exec, execOut: brokenExecOut, cmd, fileExists: () => true });
  assert.equal(status.installed, true);
  assert.equal(status.stale, true);
  assert.equal(status.reason, "unreadable");
});

test("doctor check: FAILS on a stale registration, PASSES when the scheme is simply not registered", () => {
  const reg = fakeWindowsRegistry();

  // Off by default (opt-in) — that is a healthy machine, not a fault.
  const off = protocolDoctorCheck({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => true });
  assert.equal(off.name, "protocol_handler_valid");
  assert.equal(off.pass, true);
  assert.match(off.detail, /opt-in/);

  installProtocol({ plat: "win32", exec: reg.exec, cmd });
  const broken = protocolDoctorCheck({ plat: "win32", exec: reg.exec, execOut: reg.execOut, cmd, fileExists: () => false });
  assert.equal(broken.name, "protocol_handler_valid");
  assert.equal(broken.pass, false, "doctor must report a dead registration instead of reporting healthy");
  assert.match(broken.detail, /no longer exists/);
});

test("doctor check: an unreadable registration is a FAIL, not an assumed-healthy one", () => {
  const check = protocolDoctorCheck({
    plat: "win32",
    exec: () => {}, // query succeeds -> "installed"
    execOut: () => "HKEY_CURRENT_USER\\...\\command\r\n    SomethingElse    REG_SZ    x\r\n",
    cmd,
    fileExists: () => true,
  });
  assert.equal(check.name, "protocol_handler_valid");
  assert.equal(check.pass, false);
  assert.match(check.detail, /could not be read back/);
});

// macOS code is a separate WU (spec §3.2 is FLAG-AND-WAIT on the .app-bundle
// wrapper) — the unsupported stub must hold for darwin, never throw. Linux
// stopped being an unsupported platform in HELM-PROTO-3 and is covered by the
// section below.
test("unsupported platforms: report unsupported, never throw", () => {
  for (const plat of ["darwin"]) {
    assert.deepEqual(installProtocol({ plat, exec: () => {} }), { ok: false, supported: false });
    assert.deepEqual(uninstallProtocol({ plat, exec: () => {} }), { ok: false, supported: false });
    assert.equal(isProtocolInstalled({ plat, exec: () => {} }), false);
    assert.equal(protocolLocation({ plat }), null);

    const status = protocolStatus({ plat, exec: () => {}, execOut: () => "" });
    assert.equal(status.supported, false);
    assert.equal(status.stale, false);
    assert.equal(status.reason, "unsupported");
    assert.equal(status.expected, null);

    const check = protocolDoctorCheck({ plat, exec: () => {}, execOut: () => "" });
    assert.equal(check.name, "protocol_handler_valid");
    assert.equal(check.pass, true);
  }
});

// HELM-AUTOSTART-1's consent rule extended to the scheme (spec §3): the
// daemon's start path must contain NO installer call at all — registration
// happens only through the pairing tab's opt-in toggle (POST /autostart) or
// `helmd uninstall` (spec §9 gate 5's daemon-side half). Asserted against the
// source rather than by booting a first-run daemon, because the only honest
// way to test the boot version is to let it write to the real registry of
// whatever machine runs the suite — which is the exact act being forbidden.
test("index.mjs: no start path calls the protocol installer", () => {
  const source = readFileSync(new URL("./index.mjs", import.meta.url), "utf8");
  // Strip comments — this file explains at length WHY the installers were
  // removed from the boot path, and those explanations name them.
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  // \b so "uninstallProtocol" — which contains "installProtocol" — doesn't
  // trip this. The uninstall path is allowed; the install path is not.
  assert.doesNotMatch(code, /\binstallProtocol\b/, "helmd must never register helm:// without an explicit user action");
  // uninstall stays: `helmd uninstall` is itself an explicit user action.
  assert.match(code, /\buninstallProtocol\b/);
});

// ———— Linux (HELM-PROTO-3, spec §3.3) ————
// Same SHAPE as the Windows tests, different internals: the .desktop file is
// plain text on disk, so the round-trip (write it, read it back, delete it)
// runs for REAL against a temp per-user applications directory; only the
// xdg-mime / update-desktop-database shell-outs are faked — the same
// never-touch-the-real-OS-surface discipline as the fake registry above.
// `exec`/`execOut` assert the exact freedesktop calls, the way the Windows
// fake asserts the exact reg calls.
function fakeLinuxDesktop({ queriedDefault = DESKTOP_FILE_NAME } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "helm-proto3-"));
  const calls = [];
  const state = { queriedDefault };
  const exec = (bin, args) => {
    calls.push([bin, args]);
    if (bin === "xdg-mime") {
      // The registration call must be EXACTLY the standard freedesktop.org
      // one — same shell-out pattern as openBrowser()'s `xdg-open` (index.mjs).
      if (args[0] !== "default" || args[1] !== DESKTOP_FILE_NAME || args[2] !== HELM_SCHEME) {
        throw new Error(`unexpected xdg-mime call: ${args.join(" ")}`);
      }
      state.queriedDefault = DESKTOP_FILE_NAME; // the mimeapps.list write it performs
      return;
    }
    if (bin === "update-desktop-database") return; // best-effort; may be absent
    throw new Error(`unexpected binary ${bin}`);
  };
  const execOut = (bin, args) => {
    calls.push([bin, args]);
    if (bin !== "xdg-mime" || args[0] !== "query" || args[1] !== HELM_SCHEME) {
      throw new Error(`unexpected query: ${bin} ${args.join(" ")}`);
    }
    return state.queriedDefault === null ? "" : `${state.queriedDefault}\n`;
  };
  const opts = {
    desktopDir: dir,
    exec,
    execOut,
    fileExists: (p) => existsSync(p),
    readFile: (p, enc) => readFileSync(p, enc),
  };
  const cleanup = () => rmSync(dir, { recursive: true, force: true });
  return { dir, calls, state, opts, cleanup };
}

test("Linux: the .desktop entry is a fixed literal — Exec + MimeType, no % field code anywhere", () => {
  const content = desktopEntryContent(linuxCmd);
  assert.match(content, /^\[Desktop Entry\]$/m);
  assert.equal(/^Type=(.*)$/m.exec(content)[1], "Application");
  assert.equal(/^MimeType=(.*)$/m.exec(content)[1], "x-scheme-handler/helm;", "the scheme declaration the registration is FOR");

  // The Linux half of spec §9 gate 1: exactly one templated byte sequence
  // (the binary path), fixed arguments, and — because freedesktop launches
  // .desktop entries by substituting % field codes — no % ANYWHERE, so a
  // scheme invocation has no channel through which its URL could ride along.
  assert.equal(/^Exec=(.*)$/m.exec(content)[1], '"/opt/helm/bin/helmd" open --from-scheme');
  assert.match(content, /^Exec="[^"]*" open --from-scheme$/m, "exactly one templated byte sequence allowed: the binary path");
  assert.doesNotMatch(content, /%/, "no freedesktop field code — no argument channel (spec §2)");
});

test("Linux: desktopExecValue quotes what needs quoting — spaces in path or dev-checkout entry", () => {
  assert.equal(desktopExecValue({ command: "/opt/my apps/helmd", args: ["open", FROM_SCHEME_FLAG] }), '"/opt/my apps/helmd" open --from-scheme');
  // Dev-checkout shape (protocolCommand): process.execPath + the entry script.
  assert.equal(desktopExecValue({ command: "/usr/bin/node", args: ["/home/me/helm hub/index.mjs", "open", FROM_SCHEME_FLAG] }), '"/usr/bin/node" "/home/me/helm hub/index.mjs" open --from-scheme');
  assert.equal(desktopExecValue({ command: "/opt/helm/bin/helmd", args: ["open", FROM_SCHEME_FLAG] }), '"/opt/helm/bin/helmd" open --from-scheme');
});

test("Linux: install writes the entry and registers via exactly the standard xdg-mime call", () => {
  const env = fakeLinuxDesktop();
  try {
    assert.equal(isProtocolInstalled({ plat: "linux", ...env.opts }), false, "nothing before install");

    const result = installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });
    assert.equal(result.ok, true);
    assert.equal(result.value, desktopExecValue(linuxCmd));
    assert.equal(isProtocolInstalled({ plat: "linux", ...env.opts }), true, "present after install");

    // The file on disk is the registration — read it back for real.
    const content = readFileSync(join(env.dir, DESKTOP_FILE_NAME), "utf8");
    assert.equal(/^Exec=(.*)$/m.exec(content)[1], desktopExecValue(linuxCmd));
    assert.equal(/^MimeType=(.*)$/m.exec(content)[1], `${HELM_SCHEME};`);

    const registrations = env.calls.filter(([bin, args]) => bin === "xdg-mime");
    assert.deepEqual(registrations, [["xdg-mime", ["default", DESKTOP_FILE_NAME, HELM_SCHEME]]], "exactly one registration call, the standard freedesktop.org shape");
  } finally {
    env.cleanup();
  }
});

test("Linux: uninstall deletes the .desktop file; update-desktop-database is best-effort and its absence is non-fatal", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });

    const result = uninstallProtocol({ plat: "linux", ...env.opts });
    assert.equal(result.ok, true);
    assert.equal(isProtocolInstalled({ plat: "linux", ...env.opts }), false, "gone after uninstall");
    assert.equal(existsSync(join(env.dir, DESKTOP_FILE_NAME)), false, "xdg-mime has no unset primitive (spec §4) — deleting the file IS the unregistration");

    // The cache refresh was attempted exactly once, and a missing tool is a
    // non-event: the removal stands either way (spec §4's documented
    // stale-cache limitation, not a bug to chase).
    assert.deepEqual(
      env.calls.filter(([bin]) => bin === "update-desktop-database").map(([bin, args]) => [bin, args[0]]),
      [["update-desktop-database", env.dir]],
    );

    const calls = [];
    const noTool = (bin) => {
      calls.push(bin);
      if (bin === "update-desktop-database") throw new Error("spawn update-desktop-database ENOENT");
    };
    const scratch = mkdtempSync(join(tmpdir(), "helm-proto3-"));
    try {
      const r2 = uninstallProtocolLinux({ exec: noTool, desktopDir: scratch });
      assert.equal(r2.ok, true, "a missing update-desktop-database never fails the uninstall");
      assert.deepEqual(calls, ["update-desktop-database"]);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  } finally {
    env.cleanup();
  }
});

test("status (Linux): entry + association both ours is ok, not stale", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });

    const status = protocolStatus({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists: () => true });
    assert.equal(status.supported, true);
    assert.equal(status.installed, true);
    assert.equal(status.stale, false);
    assert.equal(status.reason, "ok");
    assert.equal(status.recorded, desktopExecValue(linuxCmd));
    assert.equal(status.expected, desktopExecValue(linuxCmd));
    assert.equal(status.location, join(env.dir, DESKTOP_FILE_NAME));
    assert.equal(protocolLocation({ plat: "linux", desktopDir: env.dir }), join(env.dir, DESKTOP_FILE_NAME), "the location a user can find and audit by hand");
  } finally {
    env.cleanup();
  }
});

test("status (Linux): an entry whose binary is gone is STALE/target_missing, never healthy", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });

    // The entry exists; the binary it points at was moved/renamed/deleted.
    const fileExists = (p) => p === join(env.dir, DESKTOP_FILE_NAME);
    const status = protocolStatus({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists });
    assert.equal(status.installed, true);
    assert.equal(status.stale, true, "a registration pointing at a missing file must never report healthy");
    assert.equal(status.reason, "target_missing");
    assert.match(status.recorded, /helmd/);
  } finally {
    env.cleanup();
  }
});

test("status (Linux): a DISPLACED default association is stale — another handler owns helm:// now", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });
    env.state.queriedDefault = "something-else.desktop"; // another app became the default

    const status = protocolStatus({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists: () => true });
    assert.equal(status.installed, true);
    assert.equal(status.stale, true, "clicks will NOT reach Helm — this is never reported healthy");
    assert.equal(status.reason, "command_mismatch");
    assert.equal(status.recorded, "something-else.desktop", "recorded = what owns the scheme");
    assert.equal(status.expected, DESKTOP_FILE_NAME, "expected = what should own it");
  } finally {
    env.cleanup();
  }
});

test("status (Linux): the entry rewritten under our name is command_mismatch, surfaced not failed", () => {
  const env = fakeLinuxDesktop();
  try {
    // Install pointing at an OLD binary (what the file will record)…
    installProtocol({ plat: "linux", ...env.opts, cmd: { command: "/opt/helm-old/bin/helmd", args: ["open", FROM_SCHEME_FLAG] } });
    // …then ask for status against the RUNNING one, association still ours.
    const status = protocolStatus({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists: () => true });
    assert.equal(status.reason, "command_mismatch");
    assert.equal(status.stale, false, "not the displaced case: the recorded target exists and would launch a working Helm");
    assert.match(status.recorded, /helm-old/);
  } finally {
    env.cleanup();
  }
});

test("status (Linux): nothing installed reports not_installed, never stale", () => {
  const env = fakeLinuxDesktop();
  try {
    const status = protocolStatus({ plat: "linux", ...env.opts, cmd: linuxCmd });
    assert.equal(status.supported, true, "Linux is a SUPPORTED platform now (spec §3.3)");
    assert.equal(status.installed, false);
    assert.equal(status.stale, false);
    assert.equal(status.reason, "not_installed");
    assert.equal(status.recorded, null);
    assert.equal(status.expected, desktopExecValue(linuxCmd));
  } finally {
    env.cleanup();
  }
});

test("status (Linux): an entry we cannot read back is stale/unreadable, never healthy", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });

    // The file exists but says nothing we can parse as an Exec line.
    const status = protocolStatus({
      plat: "linux",
      ...env.opts,
      cmd: linuxCmd,
      fileExists: () => true,
      readFile: () => "[Desktop Entry]\nType=Application\nName=x\n",
    });
    assert.equal(status.installed, true);
    assert.equal(status.stale, true);
    assert.equal(status.reason, "unreadable");
  } finally {
    env.cleanup();
  }
});

test("status (Linux): an unanswerable association query leaves the VERIFIED entry standing — ok, not invented-stale", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });

    const status = protocolStatus({
      plat: "linux",
      ...env.opts,
      cmd: linuxCmd,
      fileExists: () => true,
      execOut: () => {
        throw new Error("spawn xdg-mime ENOENT");
      },
    });
    assert.equal(status.reason, "ok", "what was verified — the entry — is what gets reported");
    assert.equal(status.stale, false);
  } finally {
    env.cleanup();
  }
});

test("doctor check (Linux): ok passes; a displaced association FAILS with reclaim copy; a dead target fails", () => {
  const env = fakeLinuxDesktop();
  try {
    installProtocol({ plat: "linux", ...env.opts, cmd: linuxCmd });

    const healthy = protocolDoctorCheck({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists: () => true });
    assert.equal(healthy.name, "protocol_handler_valid");
    assert.equal(healthy.pass, true);

    env.state.queriedDefault = "something-else.desktop";
    const displaced = protocolDoctorCheck({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists: () => true });
    assert.equal(displaced.pass, false, "another handler owns helm:// — doctor must not report healthy");
    assert.match(displaced.detail, /reclaim/);

    env.state.queriedDefault = DESKTOP_FILE_NAME;
    const fileExists = (p) => p === join(env.dir, DESKTOP_FILE_NAME);
    const dead = protocolDoctorCheck({ plat: "linux", ...env.opts, cmd: linuxCmd, fileExists });
    assert.equal(dead.pass, false, "doctor must report a dead registration instead of reporting healthy");
    assert.match(dead.detail, /no longer exists/);
  } finally {
    env.cleanup();
  }
});
