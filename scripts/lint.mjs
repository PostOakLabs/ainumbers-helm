#!/usr/bin/env node
// Zero-dep lint gate: syntax-checks every .mjs file via node --check.
// No ESLint dep yet (D2/zero-dep-first discipline) — expand when hub/ui code lands.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "vendored"]);

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else if (entry.name.endsWith(".mjs")) out.push(p);
  }
  return out;
}

let failed = 0;
for (const file of walk(ROOT)) {
  try {
    execFileSync(process.execPath, ["--check", file], { stdio: "pipe" });
  } catch (err) {
    failed++;
    console.error(`SYNTAX ERROR: ${file}`);
    console.error(err.stderr?.toString() ?? err.message);
  }
}

if (failed > 0) {
  console.error(`lint: ${failed} file(s) failed --check`);
  process.exit(1);
}

// Live-network test guard (prevents the HELM-P2-S10 flaky-red-main class,
// 2026-07-23): a test making a REAL anchor call (FreeTSA / OTS calendar) must
// gate it via liveTest() from test-support/live.mjs, so the blocking suite
// stays offline/deterministic and a third-party hiccup can't redden main.
const LIVE_CALL = /\bawait\s+(?:anchorRfc3161|anchorOpenTimestamps|verifyGithubPat)\s*\(/;
let liveViol = 0;
for (const file of walk(ROOT)) {
  if (!file.endsWith(".test.mjs")) continue;
  const src = readFileSync(file, "utf8");
  if (LIVE_CALL.test(src) && !/\bliveTest\s*\(/.test(src)) {
    liveViol++;
    console.error(`LIVE-NET GATE: ${file} makes a live anchor call but has no liveTest() wrapper — wrap it via test-support/live.mjs so it can't redden main.`);
  }
}
if (liveViol > 0) {
  console.error(`lint: ${liveViol} live-network gate violation(s)`);
  process.exit(1);
}

// Google OAuth scope lint (HELM-P3-U4, P3-D5): forbid drive.readonly/drive
// anywhere in the repo — see scripts/lib/google-scope-lint.mjs.
const { scanRepoForForbiddenGoogleScopes } = await import("./lib/google-scope-lint.mjs");
const scopeViolations = scanRepoForForbiddenGoogleScopes(ROOT);
if (scopeViolations.length > 0) {
  console.error("GOOGLE SCOPE LINT: forbidden restricted Drive scope found (drive.readonly/drive require a $500-4.5k/yr CASA assessment — use drive.file):");
  for (const v of scopeViolations) console.error(`  ${v.file}: "${v.scope}"`);
  process.exit(1);
}

console.log("lint: OK");
