import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { lintTitle } from "./pr-title-lint.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

test("lintTitle: accepts valid Conventional Commit titles", () => {
  assert.ok(lintTitle("feat: add pr-title lint"));
  assert.ok(lintTitle("fix(hub): close DNS-rebinding TOCTOU"));
  assert.ok(lintTitle("feat(release)!: breaking change to manifest format"));
  assert.ok(lintTitle("chore: bump deps"));
});

test("lintTitle: rejects non-conventional titles", () => {
  assert.equal(lintTitle("Add pr-title lint"), false);
  assert.equal(lintTitle("WIP stuff"), false);
  assert.equal(lintTitle("feat : missing colon spacing wrong type"), false);
  assert.equal(lintTitle("nope(scope): bad type"), false);
  assert.equal(lintTitle(""), false);
});

test("lintTitle: rejects the real CI failures (runs 30061089932/30087980537/30088100988)", () => {
  assert.equal(lintTitle("HELM-P3-U2: Browser journal + durability UX"), false); // WU-ID as type
  assert.equal(lintTitle("helm-ui: browser vault — PRF wraps DEK, passphrase fallback (HELM-P3-U3)"), false); // non-allowed type
  assert.equal(lintTitle("helm testiso 1"), false); // no type at all
});

test("lintTitle: accepts the corrected forms of those failures", () => {
  assert.ok(lintTitle("feat(ui): browser journal + durability UX (HELM-P3-U2)"));
  assert.ok(lintTitle("feat(helm-ui): browser vault, PRF wraps DEK (HELM-P3-U3)"));
  assert.ok(lintTitle("chore: testiso 1"));
});

function runWithEvent(title) {
  const tmp = mkdtempSync(join(tmpdir(), "helm-pr-title-lint-test-"));
  const eventPath = join(tmp, "event.json");
  writeFileSync(eventPath, JSON.stringify({ pull_request: { title } }));
  try {
    execFileSync(process.execPath, [join(HERE, "pr-title-lint.mjs")], {
      env: { ...process.env, GITHUB_EVENT_PATH: eventPath },
      stdio: "pipe",
    });
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

test("CLI: fails a non-conventional title", () => {
  assert.throws(() => runWithEvent("Add a thing"));
});

test("CLI: passes a valid Conventional Commit title", () => {
  assert.doesNotThrow(() => runWithEvent("fix(ci): pass a valid title"));
});
