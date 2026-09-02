// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// HELM-PROTO-2 (HELM-PROTO-BUILD-SPEC §5, §9 gate 1): the helm:// scheme
// registration invokes the binary itself as `helmd open --from-scheme`, so a
// scheme click with no daemon running must end in a started daemon + an
// opened dashboard tab — the same outcome as a Start Menu double-click, via
// the SAME code path (cmdStart's existing first-run/--open browser gate,
// reused as-is; no new gate, no new consent surface). Plain `helmd open`
// keeps its client contract: exit 1 when nothing is listening.
//
// Tests 1-3 are E2E, same shape as cli-verbs.test.mjs / winspam-regression
// .test.mjs (top-level-await CLI entry, can't be unit tested by import).
// HELM_NO_OPEN=1, like every suite in this repo: openBrowser logs
// "auto-opening browser tab" BEFORE the suppression check, so the tab-open
// signal survives without hijacking a real browser. The token is pre-seeded,
// making the scheme-launched boot a RETURNING run — which alone would NOT
// open a tab (HELM-WINSPAM-1) — so a fired opener proves the fallthrough
// really passed `open: true`, not first-run luck.
//
// Test 4 is the §9 gate 1 half, asserted against the source the same way
// protocol.test.mjs pins its fixed literal: `--from-scheme` is a MARKER —
// the one fixed literal the scheme adds — never templated, never an
// argument channel. No byte of any scheme-invocation string is parsed.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, execFileSync } from "node:child_process";
import { FROM_SCHEME_FLAG } from "./protocol.mjs";

const TMP = mkdtempSync(join(tmpdir(), "helm-from-scheme-"));
process.env.HELM_HOME = TMP;

const PORT = 41781;
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: `http://127.0.0.1:${PORT}`, versionCheckUrl: "" }));

// Pre-creating the token is what makes the scheme-launched boot below a
// RETURNING run (see header) — same trick as cli-verbs.test.mjs.
const { loadOrCreateToken } = await import("./token.mjs");
loadOrCreateToken();

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
const ENV = { ...process.env, HELM_HOME: TMP, HELM_NO_OPEN: "1" };

let daemon;
after(async () => {
  if (daemon && daemon.exitCode === null) {
    // kill(1) on Windows is async — the journal db stays locked until the
    // child actually closes, and an immediate rmSync races it (EPERM).
    const closed = new Promise((resolve) => daemon.on("close", resolve));
    daemon.kill();
    await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, 3000))]);
  }
  rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
});

function helmd(...args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [ENTRY, ...args], { env: ENV, encoding: "utf8" }) };
  } catch (err) {
    return { code: err.status, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

function waitForRunning(child) {
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`daemon did not report ready:\n${out}`)), 20000);
    child.stdout.on("data", (c) => {
      out += c.toString("utf8");
      if (out.includes("Helm is running.")) {
        clearTimeout(timer);
        resolve(out);
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`daemon exited early with ${code}:\n${out}`));
    });
  });
}

// "close", not "exit" — same pipe-draining rationale as winspam-regression.
function waitForClose(child) {
  return new Promise((resolve) => child.on("close", resolve));
}

test("scheme click with no daemon running: `open --from-scheme` starts the daemon AND opens the tab", async () => {
  // The exact invocation shape the Windows registration writes
  // (protocol.mjs protocolCommand): the binary, `open`, the marker flag —
  // no other argument, nothing from any invoking URL.
  daemon = spawn(process.execPath, [ENTRY, "open", FROM_SCHEME_FLAG], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  let allOutput = "";
  daemon.stdout.on("data", (c) => (allOutput += c.toString("utf8")));

  // The open verb itself became the daemon — a started daemon, from a click
  // that found nothing listening (spec §5's stopped-but-installed leg).
  const startupOutput = await waitForRunning(daemon);
  // The fallthrough is visible and ordered: the marker's "starting helmd"
  // log lands BEFORE the boot banner that waitForRunning resolved on.
  assert.match(startupOutput, /no daemon running — starting helmd/, "the isNotRunning fallthrough did not fire");
  // The tab opened on a RETURNING run (token pre-seeded above) — only the
  // fallthrough's `open: true` can explain a fired opener (HELM-WINSPAM-1
  // proves a plain returning start opens nothing). The auto-open log fires
  // AFTER the "Helm is running." banner (same ordering note as
  // cli-verbs.test.mjs), so presence needs a bounded wait on the LIVE
  // accumulator, not the resolved snapshot.
  const deadline = Date.now() + 8000;
  while (!/auto-opening browser tab/.test(allOutput)) {
    if (Date.now() > deadline || daemon.exitCode !== null) {
      assert.match(allOutput, /auto-opening browser tab/, "the scheme click must end in an opened dashboard tab");
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  // The old failure mode must be gone for a scheme click.
  assert.doesNotMatch(allOutput, /no daemon listening/);

  // The started daemon is a real one: the CLI channel answers, and it stops
  // cleanly (the idle timer, not the click, owns its lifetime from here).
  const status = helmd("status");
  assert.equal(status.code, 0);
  assert.match(status.out, /running \(pid \d+\)/);

  // Already-running leg of spec §5 (same click shape, daemon now up): the
  // pair path answers — prints a pairing URL, exits 0, starts NO second
  // daemon.
  const again = helmd("open", FROM_SCHEME_FLAG);
  assert.equal(again.code, 0, again.out);
  assert.match(again.out, /token=/, "the already-running path prints the pairing URL");
  assert.doesNotMatch(again.out, /Helm is running/, "no second daemon may boot for an already-running click");

  const exited = new Promise((resolve) => daemon.on("exit", resolve));
  const stop = helmd("stop");
  assert.equal(stop.code, 0, stop.out);
  assert.match(stop.out, /helmd stopped/);
  assert.equal(await exited, 0);
});

test("plain `helmd open` (no flag) with no daemon still exits 1 — the client contract is unchanged", () => {
  const open = helmd("open");
  assert.equal(open.code, 1, "without --from-scheme a not-running daemon is still a branchable exit 1");
  assert.match(open.out, /no daemon listening/);
});

// HELM-PROTO-BUILD-SPEC §9 gate 1, CLI-side half (protocol.test.mjs pins the
// registration side): `--from-scheme` is a fixed literal, never templated,
// and cmdOpen gained no argument-parsing surface. Asserted against the
// source — comments stripped, same as protocol.test.mjs's consent-rule test.
test("gate 1: the scheme's only argv footprint is the fixed-literal presence check", () => {
  const source = readFileSync(new URL("./index.mjs", import.meta.url), "utf8");
  const code = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

  // The flag enters the file exactly twice, both as the SAME symbol: the
  // import and the dispatch check. No second spelling of the literal, no
  // third use to template anything from.
  assert.equal((code.match(/FROM_SCHEME_FLAG/g) || []).length, 2, "FROM_SCHEME_FLAG: import + dispatch only");
  assert.doesNotMatch(code, /--from-scheme/, "the literal must live only in protocol.mjs — no re-spelling here");

  // process.argv is read exactly once, in the dispatch prologue — the open
  // path's only argv-derived value is the boolean presence of the marker.
  assert.equal((code.match(/\bprocess\.argv\b/g) || []).length, 1, "no new argv reader anywhere in index.mjs");
  assert.match(code, /cmd === "open"\) await cmdOpen\(\{ fromScheme: args\.includes\(FROM_SCHEME_FLAG\) \}\);/);

  // cmdOpen itself takes only the marker boolean and never touches argv or
  // the args array — nothing exists to carry a byte of the invoking URL.
  const fn = code.match(/async function cmdOpen\(\{ fromScheme = false \} = \{\}\) \{[\s\S]*?\n\}/);
  assert.ok(fn, "cmdOpen signature not found");
  assert.doesNotMatch(fn[0], /\bargs\b/, "cmdOpen must not read the argv array");
  assert.doesNotMatch(fn[0], /process\.argv/, "cmdOpen must not read process.argv");

  // The fallthrough target is pinned: the existing cmdStart gate, as-is.
  assert.match(code, /if \(fromScheme && isNotRunning\(err\)\)/);
  assert.match(code, /return cmdStart\(\{ open: true \}\);/);
});
