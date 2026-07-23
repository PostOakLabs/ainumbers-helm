import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

function initRepo() {
  const dir = mkdtempSync(join(tmpdir(), "pushed-commits-test-"));
  const git = (...args) => execFileSync("git", args, { cwd: dir, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  git("config", "user.email", "test@example.com");
  git("config", "user.name", "Test");
  return { dir, git };
}

function commit(git, dir, subject) {
  writeFileSync(join(dir, "f.txt"), `${Math.random()}`);
  git("add", "-A");
  git("commit", "-q", "-m", subject);
}

function runCheck(dir, range) {
  try {
    execFileSync("node", [join(HERE, "check-pushed-commits.mjs"), range], { cwd: dir, encoding: "utf8" });
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
