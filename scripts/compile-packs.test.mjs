import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "./lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PACKS_DIR = join(ROOT, "packs");
const SCHEMA = JSON.parse(readFileSync(join(ROOT, "schema", "workflow-manifest.schema.json"), "utf8"));

function run(args) {
  return execFileSync(process.execPath, [join(ROOT, "scripts", "compile-packs.mjs"), ...args], {
    cwd: ROOT,
    stdio: "pipe",
  }).toString();
}

test("compile-packs: compiles a non-empty subset and skips the rest with logged reasons", () => {
  run([]);
  const index = JSON.parse(readFileSync(join(PACKS_DIR, "INDEX.json"), "utf8"));
  assert.ok(index.compiledCount > 0, "expected at least one compiled pack");
  assert.ok(index.skippedCount > 0, "expected at least one skip (not every site chain is a pure kernel DAG)");
  assert.equal(index.compiledCount + index.skippedCount > 0, true);
  for (const skip of index.skips) {
    assert.ok(skip.name && skip.reason, "every skip MUST carry a name + reason — no silent truncation");
  }

  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  assert.equal(packFiles.length, index.compiledCount);
});

test("compile-packs: every emitted pack's manifest validates against schema/workflow-manifest.schema.json", () => {
  run([]);
  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  for (const file of packFiles) {
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, file), "utf8"));
    const errs = validate(SCHEMA, pack.manifest);
    assert.deepEqual(errs, [], `${file}: manifest failed schema validation: ${errs.join(", ")}`);
    assert.ok(/^sha256:[0-9a-f]{64}$/.test(pack.workflow_manifest_digest));
  }
});

test("compile-packs: --check passes on freshly generated packs/, fails after a tamper", () => {
  run([]);
  run(["--check"]); // should not throw

  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  const victim = join(PACKS_DIR, packFiles[0]);
  const original = readFileSync(victim, "utf8");
  const tampered = JSON.parse(original);
  tampered.name = "TAMPERED";
  writeFileSync(victim, JSON.stringify(tampered, null, 2) + "\n");

  assert.throws(() => run(["--check"]), /Command failed/);

  writeFileSync(victim, original); // restore — leave packs/ fresh for other tests/CI steps
});
