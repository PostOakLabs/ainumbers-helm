#!/usr/bin/env node
// Zero-dep test runner: executes every *.test.mjs under fixtures/ and hub/ via node:test.
import { run } from "node:test";
import { tap } from "node:test/reporters";
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// .wt/.worktrees: sibling git worktrees for other in-flight WUs sometimes
// live inside the repo root (workspace convention) — their *.test.mjs files
// belong to a different checkout/branch and must never be picked up by this
// walk (a stray mid-edit file there crashed a parallel WU's pre-push run).
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "vendored", ".wt", ".worktrees"]);

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
