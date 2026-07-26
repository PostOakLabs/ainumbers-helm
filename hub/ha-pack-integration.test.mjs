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
const { recordsForSubject } = await import("./ha-store.mjs");
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

// BANK-GENIUS-HPACK-1: GENIUS Act monthly reserve cert as a gated reference
// pack — CEO/CFO dual_control(2) countersignature over helmd's real §27.2
// producer, same instrument HELM-HA-1 proved generically, now over a
// production compiled pack for the statutory monthly-recurring use case.
const GENIUS_WORKFLOW_ID = "pack-genius-reserve-disclosure";

test("compiled pack: pack-genius-reserve-disclosure's n1 carries the dual_control(2) overlay", () => {
  const pack = getPack(GENIUS_WORKFLOW_ID);
  assert.ok(pack, "expected pack-genius-reserve-disclosure to have compiled — run `node scripts/compile-packs.mjs` first");
  const gated = pack.manifest.nodes.find((n) => n.node_id === "n1");
  assert.equal(gated.gate_policy, "dual_control");
  assert.equal(gated.gate_role, "approver");
  assert.equal(gated.gate_threshold, 2);
});

test("run engine over the real compiled GENIUS pack: one identity approving twice is NOT enough", async () => {
  const pack = getPack(GENIUS_WORKFLOW_ID);
  const db = dbAt("genius-run-1.db");
  const stepRunner = async (step) => ({ dry_run: true, step_id: step.step_id });

  const held = await executeRun(db, { runId: "genius-run-1", manifest: pack.manifest, dryRun: true, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");
  assert.equal(held.held.step_id, "nodes:n1");

  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("genius-run-1"));
  assert.equal(foundHold.gatePolicy, "dual_control");

  const ceo = await newIdentity();
  for (const ts of ["2026-07-25T12:00:00Z", "2026-07-25T12:05:00Z"]) {
    const record = await signHaRecord(
      { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: ceo.id }, decision: "approve", timestamp: ts },
      ceo, { nowISO: ts }
    );
    await submitHaRecord(db, record);
  }

  const stillHeld = await executeRun(db, { runId: "genius-run-1", manifest: pack.manifest, dryRun: true, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(stillHeld.state, "awaiting_data", "same identity approving twice must not satisfy dual_control(2)");
  db.close();
});

test("run engine over the real compiled GENIUS pack: CEO + CFO distinct attestations resume the cert", async () => {
  const pack = getPack(GENIUS_WORKFLOW_ID);
  const db = dbAt("genius-run-2.db");
  const stepRunner = async (step) => ({ dry_run: true, step_id: step.step_id });

  const held = await executeRun(db, { runId: "genius-run-2", manifest: pack.manifest, dryRun: true, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");
  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("genius-run-2"));

  const ceo = await newIdentity();
  const cfo = await newIdentity();
  for (const [signer, ts] of [[ceo, "2026-07-25T12:00:00Z"], [cfo, "2026-07-25T13:00:00Z"]]) {
    const record = await signHaRecord(
      { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: signer.id }, decision: "approve", timestamp: ts },
      signer, { nowISO: ts }
    );
    await submitHaRecord(db, record); // evidence bundle: both the CEO's and the CFO's signed §27.2 records land in the same HA store, keyed by this run's subject_hash
  }

  const resumed = await executeRun(db, { runId: "genius-run-2", manifest: pack.manifest, dryRun: true, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(resumed.state, "completed");

  const records = recordsForSubject(db, foundHold.subjectHash);
  const distinctApprovers = new Set(records.filter((r) => r.decision === "approve").map((r) => r.identity.id));
  assert.equal(distinctApprovers.size, 2, "evidence bundle must carry both the CEO and CFO attestations");
  db.close();
});
