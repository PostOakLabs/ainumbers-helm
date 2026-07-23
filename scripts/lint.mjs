#!/usr/bin/env node
// Zero-dep lint gate: syntax-checks every .mjs file via node --check.
// No ESLint dep yet (D2/zero-dep-first discipline) — expand when hub/ui code lands.
import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
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
console.log("lint: OK");
