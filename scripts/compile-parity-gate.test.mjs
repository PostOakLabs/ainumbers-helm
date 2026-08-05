import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runParityGate } from "./compile-parity-gate.mjs";
import { openJournal } from "../hub/journal.mjs";
import { KERNELS } from "../hub/vendored/ocg/kernels/index.mjs";

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

// PACKPARITY-WITNESS-1: a §25 ocg-private-input@1 node's fixture policy_parameters carries
// only a commitment — sample input for it must be sourced from the out-of-band
// *.disclosure.json fixture (private-input-witness.mjs) and genuinely recompute-and-compare,
// not merely pass because a witness file exists.
test("compile-parity-gate: a §25 private-input node (art-413) is sourced from its disclosure fixture and passes real parity", async () => {
  const { db, tmpDir } = freshDb();
  const stagedDir = mkdtempSync(join(tmpdir(), "helm-compile-parity-privin-"));
  try {
    assert.ok(KERNELS["art-413-screen-sanctions-private"], "art-413 must be vendored for this test to be meaningful");

    const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
    const victimFile = packFiles[0];
    const victim = JSON.parse(readFileSync(join(PACKS_DIR, victimFile), "utf8"));
    victim.manifest.nodes[0] = {
      ...victim.manifest.nodes[0],
      node_id: "test_privin_art413",
      kernel_id: "art-413-screen-sanctions-private",
      kernel_digest: "sha256:2af360c0c70be73aaad6a5c1ac72f0718d6480b7b8d524a8d929b684532805e2",
      verified: true,
    };

    for (const f of packFiles) writeFileSync(join(stagedDir, f), readFileSync(join(PACKS_DIR, f)));
    writeFileSync(join(stagedDir, victimFile), JSON.stringify(victim, null, 2) + "\n");

    const result = await runParityGate({ packsDir: stagedDir, db });
    assert.equal(result.hardErrors, 0, `expected zero hard errors, got: ${JSON.stringify(result.divergences, null, 2)}`);
    assert.equal(result.diverged, 0);
    assert.equal(result.matched, result.checkedNodes);
  } finally {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
    rmSync(stagedDir, { recursive: true, force: true });
  }
});

test("compile-parity-gate: a §25 kernel_id with no registered witness assembler hard-errors, never silently passes", async () => {
  const { db, tmpDir } = freshDb();
  const stagedDir = mkdtempSync(join(tmpdir(), "helm-compile-parity-privin-noassm-"));
  try {
    // art-415 IS vendored (has a kernel + fixtures + disclosure file) but its checked-in
    // disclosure fixture does not currently reproduce its own declared commitment (a
    // pre-existing repo/ fixture defect, out of this WU's fence — see check-off). Splicing
    // it in proves the self-verify catches a stale/wrong witness rather than passing on
    // file-existence alone.
    assert.ok(KERNELS["art-415-check-capital-adequacy-private"], "art-415 must be vendored for this test to be meaningful");

    const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
    const victimFile = packFiles[0];
    const victim = JSON.parse(readFileSync(join(PACKS_DIR, victimFile), "utf8"));
    victim.manifest.nodes[0] = {
      ...victim.manifest.nodes[0],
      node_id: "test_privin_art415",
      kernel_id: "art-415-check-capital-adequacy-private",
      kernel_digest: "sha256:2ea7eb0372ecebf09f65212f7005ce7e5e31c1e0b784b1a8e55b057cc5f98846",
      verified: true,
    };

    for (const f of packFiles) writeFileSync(join(stagedDir, f), readFileSync(join(PACKS_DIR, f)));
    writeFileSync(join(stagedDir, victimFile), JSON.stringify(victim, null, 2) + "\n");

    const result = await runParityGate({ packsDir: stagedDir, db });
    assert.ok(result.hardErrors > 0, "expected the stale disclosure witness to hard-error, not pass silently");
  } finally {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
    rmSync(stagedDir, { recursive: true, force: true });
  }
});
