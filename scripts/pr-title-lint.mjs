#!/usr/bin/env node
// Zero-dep Conventional Commits lint for PR titles (HELM-REL-AUTO-2, A3).
// Reads the PR title from the pull_request event payload and fails the
// process if it does not match `type(scope)!: subject`. Keeps
// release-please's squash-merge-title version calc reliable.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const ALLOWED_TYPES = ["feat", "fix", "docs", "chore", "refactor", "perf", "test", "build", "ci", "revert"];

const CONVENTIONAL_COMMIT_RE = new RegExp(`^(${ALLOWED_TYPES.join("|")})(\\([^)]+\\))?!?: .+$`);

export function lintTitle(title) {
  return CONVENTIONAL_COMMIT_RE.test(title);
}

function readTitleFromEvent(eventPath) {
  const event = JSON.parse(readFileSync(eventPath, "utf8"));
  const title = event?.pull_request?.title;
  if (typeof title !== "string") {
    throw new Error("pr-title-lint: no pull_request.title found in event payload");
  }
  return title;
}

function main() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) {
    console.error("pr-title-lint: GITHUB_EVENT_PATH not set (run this in a pull_request workflow)");
    process.exit(1);
  }

  const title = readTitleFromEvent(eventPath);

  if (!lintTitle(title)) {
    console.error(`pr-title-lint: PR title "${title}" is not a valid Conventional Commit.`);
    console.error(`Required format: type(optional-scope)!: subject`);
    console.error(`Allowed types: ${ALLOWED_TYPES.join(", ")}`);
    process.exit(1);
  }

  console.log(`pr-title-lint: "${title}" ok`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
