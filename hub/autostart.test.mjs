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

test("macOS: install writes a LaunchAgent plist with RunAtLoad + KeepAlive true", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-autostart-mac-"));
  const calls = [];
  const exec = (bin, args) => calls.push([bin, args]);
  try {
    const result = installAutostart({ plat: "darwin", home, exec, cmd });
    assert.equal(result.ok, true);
    assert.equal(isAutostartInstalled({ plat: "darwin", home }), true);

    const plist = readFileSync(launchAgentPath(home), "utf8");
    assert.match(plist, /<key>RunAtLoad<\/key>\s*<true\/>/);
    assert.match(plist, /<key>KeepAlive<\/key>\s*<true\/>/);
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

test("unsupported platform (linux): reports unsupported, never throws", () => {
  assert.deepEqual(installAutostart({ plat: "linux", exec: () => {}, cmd }), { ok: false, supported: false });
  assert.deepEqual(uninstallAutostart({ plat: "linux", exec: () => {} }), { ok: false, supported: false });
  assert.equal(isAutostartInstalled({ plat: "linux", exec: () => {} }), false);
});
