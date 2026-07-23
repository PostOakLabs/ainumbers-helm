import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runParityGate } from "./compile-parity-gate.mjs";
import { openJournal } from "../hub/journal.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PACKS_DIR = join(ROOT, "packs");

function freshDb() {
  const tmpDir = mkdtempSync(join(tmpdir(), "helm-compile-parity-test-"));
  return { db: openJournal(join(tmpDir, "parity.db")), tmpDir };
}

test("compile-parity-gate: every compiled pack's nodes are byte-identical to the canonical kernel run", async () => {
  const { db, tmpDir } = freshDb();
  try {
    const result = await runParityGate({ db });
    assert.equal(result.hardErrors, 0, "expected zero hard errors");
    assert.equal(result.diverged, 0, `expected zero divergences, got: ${JSON.stringify(result.divergences, null, 2)}`);
    assert.ok(result.checkedPacks > 0, "expected at least one compiled pack to check");
    assert.equal(result.matched, result.checkedNodes);
  } finally {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("compile-parity-gate: a tampered kernel_digest pin is caught, not silently passed", async () => {
  const { db, tmpDir } = freshDb();
  const stagedDir = mkdtempSync(join(tmpdir(), "helm-compile-parity-tamper-"));
  try {
    const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
    const victimFile = packFiles[0];
    const victim = JSON.parse(readFileSync(join(PACKS_DIR, victimFile), "utf8"));

    // Corrupt the D2 pin (kernel_digest) on the first node without touching kernel_id —
    // exactly the "stale or tampered pin" scenario kernel-runner.mjs's own comment
    // describes. helmd's runKernelNode MUST reject this before ever reaching a hash
    // comparison; the gate must surface that as a hard error, not a silent pass.
    victim.manifest.nodes[0].kernel_digest = "sha256:" + "0".repeat(64);

    for (const f of packFiles) writeFileSync(join(stagedDir, f), readFileSync(join(PACKS_DIR, f)));
    writeFileSync(join(stagedDir, victimFile), JSON.stringify(victim, null, 2) + "\n");

    const result = await runParityGate({ packsDir: stagedDir, db });
    assert.ok(result.hardErrors > 0, "expected the tampered kernel_digest to hard-error, not pass silently");
  } finally {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
    rmSync(stagedDir, { recursive: true, force: true });
  }
});
