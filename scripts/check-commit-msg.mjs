#!/usr/bin/env node
// Validate a commit subject against the SAME Conventional Commit rule the
// `PR Title Lint` CI job enforces on PR titles (HELM-SHIFTLEFT-1). Imports
// `lintTitle()` from pr-title-lint.mjs — one validator, so local and CI can
// never drift. Invoked by .githooks/commit-msg with the commit-msg file path.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { lintTitle } from "./pr-title-lint.mjs";

export function firstLine(message) {
  return message.split("\n")[0].trim();
}

function main() {
  const msgFile = process.argv[2];
  if (!msgFile) {
    console.error("check-commit-msg: no commit-msg file path given");
    process.exit(1);
  }

  const subject = firstLine(readFileSync(msgFile, "utf8"));

  // Merge commits don't carry a Conventional Commit subject — nothing to gate.
  if (subject.startsWith("Merge ")) {
    process.exit(0);
  }

  if (!lintTitle(subject)) {
    console.error(`check-commit-msg: commit subject "${subject}" is not a valid Conventional Commit.`);
    console.error(`Required format: type(optional-scope)!: subject`);
    console.error(`Put the WU-ID in the scope or body, never the type:`);
    console.error(`  bad:  HELM-P3-U3: browser vault`);
    console.error(`  good: feat(helm-ui): browser vault (HELM-P3-U3)`);
    console.error(`This is the SAME rule PR Title Lint enforces in CI — fixing it here means`);
    console.error(`'gh pr create --fill' inherits a title that will already pass.`);
    process.exit(1);
  }

  console.log(`check-commit-msg: "${subject}" ok`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
