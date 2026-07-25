import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { installShortcut, uninstallShortcut, isShortcutInstalled, shortcutLocation, shortcutPathWindows } = await import("./shortcut.mjs");

const cmd = { command: "C:\\Program Files\\Helm\\helmd.exe", args: ["start"] };

// `exec` is injected everywhere below: these tests must never spawn a real
// PowerShell or write into the developer's actual Start Menu.
function recorder() {
  const calls = [];
  return { calls, exec: (bin, args) => calls.push([bin, args]) };
}

test("Windows: install creates the Start Menu directory and invokes WScript.Shell", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-shortcut-"));
  const { calls, exec } = recorder();
  try {
    const result = installShortcut({ plat: "win32", home, exec, cmd });
    assert.equal(result.ok, true);
    assert.equal(result.path, shortcutPathWindows(home));
    assert.ok(existsSync(join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs")));

    const [bin, args] = calls[0];
    assert.equal(bin, "powershell");
    assert.deepEqual(args.slice(0, 2), ["-NoProfile", "-NonInteractive"]);
    const script = args[3];
    assert.match(script, /CreateShortcut/);
    assert.match(script, /\$s\.Save\(\)/);
    // The shortcut must target the BINARY. A .lnk carrying the pairing URL
    // would persist a long-lived bearer token to an unprotected file and
    // reuse it across every launch.
    assert.match(script, /\$s\.TargetPath='C:\\Program Files\\Helm\\helmd\.exe'/);
    assert.equal(/token=|127\.0\.0\.1|http:/.test(script), false, "shortcut must never embed a URL or token");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("Windows: apostrophes in the home path cannot break out of the PowerShell literal", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-shortcut-quote-"));
  const { calls, exec } = recorder();
  try {
    installShortcut({ plat: "win32", home, exec, cmd: { command: "C:\\Users\\O'Brien\\helmd.exe", args: ["start"] } });
    const script = calls[0][1][3];
    // Doubled, not escaped with a backslash: that is the only correct escape
    // inside a single-quoted PowerShell literal.
    assert.match(script, /'C:\\Users\\O''Brien\\helmd\.exe'/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("Windows: install -> detected -> uninstall -> gone", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-shortcut-cycle-"));
  const { exec } = recorder();
  try {
    installShortcut({ plat: "win32", home, exec, cmd });
    assert.equal(isShortcutInstalled({ plat: "win32", home }), false, "not present until PowerShell actually writes it");

    // Simulate the .lnk PowerShell would have produced.
    const path = shortcutPathWindows(home);
    mkdirSync(join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs"), { recursive: true });
    writeFileSync(path, "lnk");
    assert.equal(isShortcutInstalled({ plat: "win32", home }), true);
    assert.equal(shortcutLocation({ plat: "win32", home }), path);

    assert.equal(uninstallShortcut({ plat: "win32", home }).ok, true);
    assert.equal(isShortcutInstalled({ plat: "win32", home }), false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("Windows: uninstall is idempotent when nothing was ever installed", () => {
  const home = mkdtempSync(join(tmpdir(), "helm-shortcut-idem-"));
  try {
    assert.equal(uninstallShortcut({ plat: "win32", home }).ok, true);
    assert.equal(uninstallShortcut({ plat: "win32", home }).ok, true);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// Reporting `supported: false` rather than a silent no-op matters: index.mjs
// only prints the "shortcut added" line when ok is true, so a silent success
// would announce a shortcut that does not exist.
test("macOS and Linux report unsupported rather than silently succeeding", () => {
  for (const plat of ["darwin", "linux"]) {
    assert.deepEqual(installShortcut({ plat, home: "/tmp/nope", exec: () => {} }), { ok: false, supported: false });
    assert.deepEqual(uninstallShortcut({ plat, home: "/tmp/nope" }), { ok: false, supported: false });
    assert.equal(isShortcutInstalled({ plat, home: "/tmp/nope" }), false);
    assert.equal(shortcutLocation({ plat, home: "/tmp/nope" }), null);
  }
});
