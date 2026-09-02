import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  installProtocol,
  uninstallProtocol,
  installProtocolWindows,
  uninstallProtocolWindows,
  isProtocolInstalled,
  protocolCommand,
  protocolCommandValue,
  protocolStatus,
  protocolDoctorCheck,
  protocolLocation,
  PROTOCOL_KEY,
  COMMAND_KEY,
  PROTOCOL_DESC,
  FROM_SCHEME_FLAG,
} from "./protocol.mjs";

const cmd = { command: "C:\\Users\\me\\Downloads\\helmd.exe", args: ["open", FROM_SCHEME_FLAG] };

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

// No macOS/Linux code in this row (spec §3.2/§3.3 are separate WUs) — but the
// unsupported stub must hold for every non-win32 platform, never throw.
test("unsupported platforms: report unsupported, never throw", () => {
  for (const plat of ["darwin", "linux"]) {
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
