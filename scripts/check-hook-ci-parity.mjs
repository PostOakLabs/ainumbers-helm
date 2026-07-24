#!/usr/bin/env node
// check-hook-ci-parity.mjs — fail if the blocking CI `ci` job runs a
// `node scripts/*.mjs` gate that the pre-push hook (.githooks/pre-push) does
// NOT run. Keeps "green pre-push == green CI" (HELM-SHIFTLEFT-1) an enforced
// invariant instead of a hand-maintained comment.
//
// WHY: the sibling worker repo shipped a bug where its pre-push aggregator
// silently drifted from CI (the §23 gate ran only in CI) and a red commit
// reached master. Helm's lists happen to be in sync today, but nothing stopped
// them from drifting — add a gate to ci.yml without touching the hook and the
// shift-left promise quietly breaks. This makes that drift a hard failure.
//
// Text-based on purpose: reads both files as source, compares script basenames.
// Zero-dep. Scoped to the `ci:` job (the blocking one) — the non-blocking
// live-net job and the tag-triggered release workflows are out of scope.
import { readFileSync } from "node:fs";
import { resolve, dirname, basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CI = resolve(ROOT, ".github/workflows/ci.yml");
const HOOK = resolve(ROOT, ".githooks/pre-push");

// Gates that legitimately run only in CI, with the reason each can't run
// pre-push. Keep tight — every entry is a hole in the shift-left promise.
const CI_ONLY = new Map([
  // (none today — the live-net job runs test.mjs, which the hook already runs,
  //  just with HELM_LIVE_NET=1; the blocking pre-push run covers the code path.)
]);

// Extract `run: node scripts/X.mjs` gates ONLY from the `ci:` job block, so a
// script that appears solely in live-net / release jobs isn't demanded of the hook.
function ciJobGates(text) {
  const lines = text.split(/\r?\n/);
  // The `ci:` job starts at a 2-space-indented `ci:` under `jobs:` and ends at
  // the next 2-space-indented `<job>:`.
  let inCi = false;
  const out = new Set();
  for (const line of lines) {
    const job = line.match(/^  ([A-Za-z0-9_-]+):\s*$/);
    if (job) { inCi = job[1] === "ci"; continue; }
    if (!inCi) continue;
    const m = line.match(/run:\s*node\s+scripts[\/\\]([\w.-]+\.mjs)/);
    if (m) out.add(basename(m[1]));
  }
  return out;
}

function hookGates(text) {
  const out = new Set();
  const re = /scripts[\/\\]([\w.-]+\.mjs)/g;
  let m;
  while ((m = re.exec(text))) out.add(basename(m[1]));
  return out;
}

function main() {
  const ci = ciJobGates(readFileSync(CI, "utf8"));
  const hook = hookGates(readFileSync(HOOK, "utf8"));
  const missing = [...ci].filter((g) => !hook.has(g) && !CI_ONLY.has(g)).sort();

  if (missing.length) {
    console.error(`✗ hook↔CI parity: ${missing.length} CI 'ci'-job gate(s) not run by .githooks/pre-push:`);
    for (const g of missing) console.error(`    - ${g}`);
    console.error(`  Add each to .githooks/pre-push (or, if it truly cannot run pre-push,`);
    console.error(`  allowlist it in CI_ONLY here with a reason).`);
    process.exit(1);
  }
  console.log(`✓ hook↔CI parity: all ${ci.size} blocking CI gates run pre-push (${CI_ONLY.size} CI-only allowlisted).`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
