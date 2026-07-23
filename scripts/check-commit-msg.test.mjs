import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { firstLine } from "./check-commit-msg.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

test("firstLine: extracts the subject from a multi-line message", () => {
  assert.equal(firstLine("feat: add thing\n\nbody text here"), "feat: add thing");
  assert.equal(firstLine("fix: one liner"), "fix: one liner");
});

function runHook(message) {
  const dir = mkdtempSync(join(tmpdir(), "commit-msg-test-"));
  const msgFile = join(dir, "MSG");
  writeFileSync(msgFile, message);
  try {
    execFileSync("node", [join(HERE, "check-commit-msg.mjs"), msgFile], { encoding: "utf8" });
    return 0;
  } catch (e) {
    return e.status ?? 1;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("check-commit-msg: accepts a valid Conventional Commit subject", () => {
  assert.equal(runHook("feat(hub): add shift-left gates"), 0);
});

test("check-commit-msg: rejects a non-Conventional subject", () => {
  assert.equal(runHook("Add shift-left gates"), 1);
});

test("check-commit-msg: allows merge commits through", () => {
  assert.equal(runHook("Merge branch 'main' into feature"), 0);
});
