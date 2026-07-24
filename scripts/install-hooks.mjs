#!/usr/bin/env node
// Activate the repo's tracked git hooks in this clone by pointing
// core.hooksPath at the committed .githooks/ dir. The commit-msg hook itself
// (.githooks/commit-msg → check-commit-msg.mjs, HELM-SHIFTLEFT-1) is already
// version-controlled — this script does NOT write it. It only fixes the one
// per-clone gap that let a bad PR title through: git never runs those hooks
// unless core.hooksPath is set, and a fresh clone doesn't set it.
//
// Wired to `npm install` via the package.json "prepare" script, so every
// clone activates hooks automatically. Safe to run repeatedly. Exits 0 (never
// breaks `npm install`) when there's no local git repo — e.g. a CI tarball
// install or when git is unavailable.
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOOKS_DIR = ".githooks";

function git(args) {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
}

try {
  // Only act inside a real work tree (skips bare/tarball/no-git contexts).
  if (git(["rev-parse", "--is-inside-work-tree"]) !== "true") {
    console.log("install-hooks: not a git work tree — skipping.");
    process.exit(0);
  }
  const current = (() => {
    try {
      return git(["config", "--get", "core.hooksPath"]);
    } catch {
      return "";
    }
  })();
  if (current === HOOKS_DIR) {
    console.log(`install-hooks: core.hooksPath already ${HOOKS_DIR} — ok.`);
    process.exit(0);
  }
  git(["config", "core.hooksPath", HOOKS_DIR]);
  console.log(`install-hooks: set core.hooksPath=${HOOKS_DIR} (activates .githooks/commit-msg).`);
} catch (err) {
  // Never fail the install — hook activation is best-effort.
  console.log(`install-hooks: skipped (${err.message.split("\n")[0]}).`);
  process.exit(0);
}
