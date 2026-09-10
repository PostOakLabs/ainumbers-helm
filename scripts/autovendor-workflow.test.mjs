// Structural gate for .github/workflows/autovendor.yml (the weekly automated
// re-vendor PR). Rides scripts/test.mjs (already CI-wired) so the workflow
// cannot silently lose its schedule, its dry-run default, its action pins,
// one of its gates, or the documented kill switch. Zero npm deps: regex
// checks over the YAML text, same shape as the other freshness gates here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const WF_PATH = join(ROOT, ".github", "workflows", "autovendor.yml");
const RELEASING_PATH = join(ROOT, "docs", "RELEASING.md");

const text = existsSync(WF_PATH) ? readFileSync(WF_PATH, "utf8") : "";
const releasing = existsSync(RELEASING_PATH) ? readFileSync(RELEASING_PATH, "utf8") : "";

test("autovendor.yml exists", () => {
  assert.ok(existsSync(WF_PATH), ".github/workflows/autovendor.yml is missing");
});

test("autovendor.yml triggers: weekly Monday 06:00 UTC cron + workflow_dispatch", () => {
  assert.match(text, /schedule:/, "no schedule trigger");
  assert.match(text, /cron: ["']0 6 \* \* 1["']/, "cron must fire Mondays 06:00 UTC");
  assert.match(text, /^\s*workflow_dispatch:/m, "no workflow_dispatch trigger");
});

test("autovendor.yml dry_run input defaults to true on manual dispatch", () => {
  const start = text.indexOf("workflow_dispatch:");
  assert.notEqual(start, -1, "workflow_dispatch block missing");
  const head = text.slice(start, start + 2000);
  const scoped = head.slice(0, searchBlockEnd(head));
  assert.match(scoped, /dry_run:/, "no dry_run input");
  assert.match(scoped, /default: true/, "dry_run must default to true");
});

// The workflow_dispatch block ends at the first top-level key after it
// (permissions:/jobs: at column 0); slice up to that line.
function searchBlockEnd(head) {
  const m = head.indexOf("\npermissions:");
  const j = head.indexOf("\njobs:");
  const candidates = [m, j].filter((i) => i !== -1);
  return candidates.length ? Math.min(...candidates) : head.length;
}

test("autovendor.yml uses only the already-pinned first-party actions", () => {
  const uses = [...text.matchAll(/^\s*uses:\s*(\S+)/gm)].map((m) => m[1]);
  assert.ok(uses.length > 0, "no uses: lines found");
  const allow = /^actions\/(checkout|setup-node|create-github-app-token)@[0-9a-f]{40}$/;
  for (const u of uses) {
    assert.match(u, allow, `unpinned or third-party action: ${u}`);
  }
});

test("autovendor.yml checks out without persisting credentials", () => {
  assert.match(text, /persist-credentials: false/, "checkout must not persist the default token");
});

test("autovendor.yml runs vendor.mjs, verify-vendored.mjs and the full test suite", () => {
  assert.match(text, /node scripts\/vendor\.mjs/, "vendor step missing");
  assert.match(text, /node scripts\/verify-vendored\.mjs/, "verify-vendored gate missing");
  assert.match(text, /node scripts\/test\.mjs/, "full test suite step missing");
});

test("autovendor.yml PR branch is autovendor/<date> and the PR carries the automerge label", () => {
  assert.match(text, /BRANCH="autovendor\/\$\(date -u \+%Y-%m-%d\)"/, "branch naming missing");
  assert.match(text, /gh pr create/, "PR creation missing");
  assert.match(text, /--label automerge/, "automerge label missing");
});

test("autovendor.yml mints the PR credential via the pinned app-token action, never GITHUB_TOKEN", () => {
  assert.match(text, /actions\/create-github-app-token@/, "app-token action missing");
  assert.match(text, /GH_TOKEN: \$\{\{ steps\.app-token\.outputs\.token \}\}/, "gh must run on the app token");
  assert.doesNotMatch(text, /github\.token/, "no GITHUB_TOKEN fallback allowed");
});

test("autovendor.yml honours the AUTOVENDOR_ENABLED kill switch", () => {
  assert.match(text, /vars\.AUTOVENDOR_ENABLED != 'false'/, "kill-switch guard missing");
});

test("docs/RELEASING.md documents the weekly PR and the stop switch", () => {
  assert.match(releasing, /autovendor\.yml/, "RELEASING.md does not mention autovendor.yml");
  assert.match(releasing, /AUTOVENDOR_ENABLED/, "RELEASING.md does not document the stop switch");
});
