#!/usr/bin/env node
// Validate every commit subject in the range being pushed (HELM-SHIFTLEFT-1).
// Reuses lintTitle() from pr-title-lint.mjs — same rule as PR Title Lint CI.
// Usage: node scripts/check-pushed-commits.mjs <range>  (e.g. "origin/main..HEAD")
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { lintTitle } from "./pr-title-lint.mjs";

export function subjectsInRange(range) {
  const out = execFileSync("git", ["log", "--format=%s", range], { encoding: "utf8" });
  return out.split("\n").filter((line) => line.length > 0);
}

function main() {
  const range = process.argv[2];
  if (!range) {
    console.error("check-pushed-commits: no commit range given");
    process.exit(1);
  }

  const subjects = subjectsInRange(range).filter((s) => !s.startsWith("Merge "));
  const bad = subjects.filter((s) => !lintTitle(s));

  if (bad.length > 0) {
    console.error("check-pushed-commits: non-Conventional-Commit subjects in this push:");
    for (const s of bad) console.error(`  - "${s}"`);
    console.error("Required format: type(optional-scope)!: subject");
    process.exit(1);
  }

  console.log(`check-pushed-commits: ${subjects.length} commit subject(s) ok`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
