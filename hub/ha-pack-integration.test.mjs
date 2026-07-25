// HELM-HA-1 §1 item 5/6: proves the §27.4 gate_policy overlay actually
// reaches a REAL compiled pack (not just a synthetic test manifest) and
// that the run engine holds/resumes it end to end — an offline conformance
// vector over production output, not a hand-rolled fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-ha-pack-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { executeRun, planSteps } = await import("./run.mjs");
const { getPack } = await import("./packs.mjs");
const { haGateCheckFor, findHeldGate, signHaRecord, submitHaRecord } = await import("./ha-gate.mjs");
const { rawPubkeyToDidKey } = await import("./vendored/ocg/kernels/_proof.mjs");

const GATED_WORKFLOW_ID = "pack-mutual-nda-composer";

function dbAt(name) {
  return openJournal(join(TMP, name));
}

async function newIdentity() {
  const keyPair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return { id: await rawPubkeyToDidKey(keyPair.publicKey), privateKey: keyPair.privateKey };
}

test("compiled pack: pack-mutual-nda-composer's n2 carries the §27.4 overlay", () => {
  const pack = getPack(GATED_WORKFLOW_ID);
  assert.ok(pack, "expected pack-mutual-nda-composer to have compiled — run `node scripts/compile-packs.mjs` first");
  const gated = pack.manifest.nodes.find((n) => n.node_id === "n2");
  assert.equal(gated.gate_policy, "review_required");
  assert.equal(gated.gate_role, "approver");
});

test("run engine over a REAL compiled pack: holds at n2, resumes after a satisfying approval", async () => {
  const pack = getPack(GATED_WORKFLOW_ID);
  const db = dbAt("pack-run.db");
  const stepRunner = async (step) => ({ dry_run: true, step_id: step.step_id }); // no kernel inputs supplied — dry-run proves the WIRING, not kernel numerics

  const held = await executeRun(db, { runId: "pack-run-1", manifest: pack.manifest, dryRun: true, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");
  assert.equal(held.held.step_id, "nodes:n2");

  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("pack-run-1"));
  assert.equal(foundHold.gatePolicy, "review_required");

  const approver = await newIdentity();
  const record = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: approver.id }, decision: "approve", timestamp: "2026-07-24T12:00:00Z" },
    approver, { nowISO: "2026-07-24T12:00:00Z" }
  );
  await submitHaRecord(db, record);

  const resumed = await executeRun(db, { runId: "pack-run-1", manifest: pack.manifest, dryRun: true, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(resumed.state, "completed");
  db.close();
});

test("compiled pack manifests without a gate_policy node are unaffected (additive only)", () => {
  const pack = getPack("pack-ai-vendor-onboarding-packet");
  const ungated = pack.manifest.nodes.filter((n) => n.node_id !== "n5");
  for (const node of ungated) assert.equal(node.gate_policy, undefined);
});
