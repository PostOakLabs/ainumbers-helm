#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Zero-dep test runner: executes every *.test.mjs under fixtures/ and hub/ via node:test.
import { run } from "node:test";
import { tap } from "node:test/reporters";
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// .wt/.worktrees/.claude: sibling git worktrees for other in-flight WUs
// sometimes live inside the repo root (workspace convention) — their
// *.test.mjs files belong to a different checkout/branch and must never be
// picked up by this walk (a stray mid-edit file there crashed a parallel WU's
// pre-push run). `.claude/worktrees` is the same hazard under a different
// name: it is listed in .git/info/exclude, so git hides it while readdirSync
// does not. A stale worktree there took a local run from 81 files to 160 —
// the entire suite running twice, concurrently. On Windows that is a
// powershell.exe spawn storm (every vault write shells out to DPAPI), and it
// surfaced as sporadic unrelated crypto failures, ~1 run in 4.
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "vendored", ".wt", ".worktrees", ".claude"]);

function walk(dir) {
  let out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(walk(p));
    else if (entry.name.endsWith(".test.mjs")) out.push(p);
  }
  return out;
}

const files = walk(ROOT);
if (files.length === 0) {
  console.log("test: no *.test.mjs files yet — nothing to run");
  process.exit(0);
}

const stream = run({ files });
let failed = false;
stream.on("test:fail", () => (failed = true));
await pipeline(stream, tap, process.stdout);
process.exitCode = failed ? 1 : 0;
