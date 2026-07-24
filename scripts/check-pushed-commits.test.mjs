import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// The pre-push hook that runs this suite is itself invoked by git, which sets
// GIT_DIR (and sometimes GIT_WORK_TREE) in the hook's process environment.
// Child git processes inherit that env and honor it over -C/cwd, so a naive
// `{ cwd: dir }` silently operates on the CALLER's real repo instead of the
// temp one — see HELM-TESTISO-1. Isolation must be structural: pass `-C`
// explicitly AND scrub any inherited GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE.
const REAL_TOPLEVEL = execFileSync("git", ["rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim();

function scrubbedEnv() {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  return env;
}

function initRepo() {
  const dir = mkdtempSync(join(tmpdir(), "pushed-commits-test-"));
  const git = (...args) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env: scrubbedEnv() });
  git("init", "-q", "-b", "main");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");

  const toplevel = git("rev-parse", "--show-toplevel").trim();
  if (toplevel === REAL_TOPLEVEL) {
    throw new Error(
      `check-pushed-commits.test.mjs: temp repo resolved to the REAL repo (${REAL_TOPLEVEL}) — ` +
        "isolation is broken, refusing to run (would corrupt the caller's branch)."
    );
  }

  return { dir, git };
}

function commit(git, dir, subject) {
  writeFileSync(join(dir, "f.txt"), `${Math.random()}`);
  git("add", "-A");
  git("commit", "-q", "-m", subject);
}

function runCheck(dir, range) {
  try {
    execFileSync("node", [join(HERE, "check-pushed-commits.mjs"), range], {
      cwd: dir,
      encoding: "utf8",
      env: scrubbedEnv(),
    });
    return 0;
  } catch (e) {
    return e.status ?? 1;
  }
}

test("check-pushed-commits: passes when every subject in range is Conventional", () => {
  const { dir, git } = initRepo();
  try {
    commit(git, dir, "chore: base");
    git("branch", "base-marker");
    commit(git, dir, "feat: add thing");
    commit(git, dir, "fix(hub): fix thing");
    assert.equal(runCheck(dir, "base-marker..HEAD"), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("check-pushed-commits: fails when any subject in range is not Conventional", () => {
  const { dir, git } = initRepo();
  try {
    commit(git, dir, "chore: base");
    git("branch", "base-marker");
    commit(git, dir, "feat: add thing");
    commit(git, dir, "Add thing without type");
    assert.equal(runCheck(dir, "base-marker..HEAD"), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
