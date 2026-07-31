import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const TMP = mkdtempSync(join(tmpdir(), "helm-ha-gate-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { executeRun, planSteps } = await import("./run.mjs");
const { pinnedKernelDigest, runKernelNode } = await import("./kernel-runner.mjs");
const { appendHaRecord } = await import("./ha-store.mjs");
const { haGateCheckFor, findHeldGate, recordReplay, signHaRecord, verifyHaRecordSignature, submitHaRecord, getSlot } = await import("./ha-gate.mjs");
const { getOrInitSlot, recordsForSubject } = await import("./ha-store.mjs");
const { sign, rawPubkeyToDidKey } = await import("./vendored/ocg/kernels/_proof.mjs");
const { validate } = await import("../scripts/lib/schema-validator.mjs");

const COUNTERSIG_SCHEMA = JSON.parse(
  readFileSync(fileURLToPath(new URL("../schema/countersignature_slot.schema.json", import.meta.url)), "utf8")
);

const KERNEL_ID = "art-324-tvm-npv";

function dbAt(name) {
  return openJournal(join(TMP, name));
}

async function newIdentity() {
  const keyPair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const id = await rawPubkeyToDidKey(keyPair.publicKey);
  return { id, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

function gatedManifest({ gatePolicy, gateThreshold } = {}) {
  return {
    manifest_version: "1",
    workflow_id: "wf-ha-gate-test",
    trigger: { type: "manual" },
    connectors: [],
    nodes: [
      {
        node_id: "n1",
        kernel_id: KERNEL_ID,
        kernel_digest: pinnedKernelDigest(KERNEL_ID),
        policy_parameters: { mode: "periods", discount_rate_pct: 10, cash_flows: [{ amount: -1000, t: 0 }, { amount: 600, t: 1 }, { amount: 600, t: 2 }] },
      },
      {
        node_id: "n2",
        kernel_id: KERNEL_ID,
        kernel_digest: pinnedKernelDigest(KERNEL_ID),
        policy_parameters: { mode: "periods", discount_rate_pct: 5, cash_flows: [{ amount: -500, t: 0 }, { amount: 300, t: 1 }] },
        gate_policy: gatePolicy,
        gate_role: "approver",
        gate_threshold: gateThreshold,
      },
    ],
    gates: [],
    actions: [],
  };
}

async function runToArtifactHash(dbName) {
  // Run just n1 (no gate) to learn the real subject_hash n2's gate will need
  // approvals for, WITHOUT tripping the gate on n2 itself.
  const db = dbAt(dbName);
  const [step] = planSteps(gatedManifest());
  const result = await runKernelNode(step, {});
  db.close();
  return result.artifact.execution_hash;
}

test("gateCheck: a step with no gate_policy is never held", async () => {
  const db = dbAt("no-gate.db");
  const gateCheck = haGateCheckFor(db);
  const [step] = planSteps(gatedManifest());
  const gate = await gateCheck(step, { priorOutputDigest: null, priorOutput: null, runId: "r" });
  assert.equal(gate.held, false);
  db.close();
});

test("run engine: a run whose gated step has no approvals HOLDS (awaiting_data), never fails or fabricates output", async () => {
  const db = dbAt("hold.db");
  const gateCheck = haGateCheckFor(db);
  const stepRunner = async (step) => runKernelNode(step, {});
  const result = await executeRun(db, { runId: "run-hold", manifest: gatedManifest({ gatePolicy: "review_required" }), stepRunner, gateCheck });

  assert.equal(result.state, "awaiting_data");
  assert.equal(result.held.step_id, "nodes:n2");
  assert.equal(result.steps.length, 1); // n1 ran; n2 held before stepRunner ever touched it
  db.close();
});

test("run engine: resuming after a satisfying approval record clears the hold and completes", async () => {
  const db = dbAt("resume.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest({ gatePolicy: "review_required" });

  const held = await executeRun(db, { runId: "run-resume", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");

  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("run-resume"));
  assert.equal(foundHold.step_id, "nodes:n2");

  const approver = await newIdentity();
  const approval = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: approver.id }, decision: "approve", timestamp: "2026-07-24T12:00:00Z" },
    approver,
    { nowISO: "2026-07-24T12:00:00Z" }
  );
  await submitHaRecord(db, approval);

  const resumed = await executeRun(db, { runId: "run-resume", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(resumed.state, "completed");
  assert.equal(resumed.steps.length, 2);
  assert.equal(await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("run-resume")), null);
  db.close();
});

test("run engine: dual_control(2) needs two DISTINCT identities — one approver twice is not enough", async () => {
  const db = dbAt("dual-control.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest({ gatePolicy: "dual_control", gateThreshold: 2 });

  const held = await executeRun(db, { runId: "run-dc", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("run-dc"));

  const approverA = await newIdentity();
  const record1 = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: approverA.id }, decision: "approve", timestamp: "2026-07-24T12:00:00Z" },
    approverA, { nowISO: "2026-07-24T12:00:00Z" }
  );
  const record2 = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: approverA.id }, decision: "approve", timestamp: "2026-07-24T12:05:00Z" },
    approverA, { nowISO: "2026-07-24T12:05:00Z" }
  );
  await submitHaRecord(db, record1);
  await submitHaRecord(db, record2);

  const stillHeld = await executeRun(db, { runId: "run-dc", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(stillHeld.state, "awaiting_data", "one identity approving twice must not satisfy N=2");

  const approverB = await newIdentity();
  const record3 = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: approverB.id }, decision: "approve", timestamp: "2026-07-24T12:10:00Z" },
    approverB, { nowISO: "2026-07-24T12:10:00Z" }
  );
  await submitHaRecord(db, record3);

  const completed = await executeRun(db, { runId: "run-dc", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(completed.state, "completed");
  db.close();
});

test("submitHaRecord: refuses a record whose signature doesn't verify (tampered decision)", async () => {
  const db = dbAt("tamper.db");
  const approver = await newIdentity();
  const record = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: "sha256:" + "9".repeat(64), identity: { id: approver.id }, decision: "approve", timestamp: "2026-07-24T12:00:00Z" },
    approver, { nowISO: "2026-07-24T12:00:00Z" }
  );
  record.decision = "reject"; // tamper AFTER signing
  await assert.rejects(submitHaRecord(db, record), /signature does not verify/);
  db.close();
});

test("recordReplay: a genuine re-execution match sets replay_verified true, tags the countersignature automated, and mints NO counting approval (MC-2.1/MC-2.3)", async () => {
  const db = dbAt("replay-match.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest();
  await executeRun(db, { runId: "run-replay", manifest, stepRunner }); // no gate — just populate step_results for n1

  // Establish the slot's maker_signature FIRST — MC-1.1 refuses any
  // countersignature over a subject with no recorded maker, so a real
  // deployment's maker act (out of this WU's scope, HELM-MAKERCHECKER
  // -BUILD-SPEC.md §0.6) is stood up here via the existing getOrInitSlot
  // capability, not a new producer.
  const [n1] = planSteps(manifest);
  const subjectHashHex = await runToArtifactHash("replay-match-probe.db");
  const subjectHash = `sha256:${subjectHashHex}`;
  const maker = await newIdentity();
  getOrInitSlot(db, subjectHash, { keyid: maker.id, sig: "probe-sig", alg: "EdDSA" });

  const checker = await newIdentity();
  const result = await recordReplay(db, { runId: "run-replay", stepId: n1.step_id, checkerIdentity: checker, nowISO: "2026-07-24T13:00:00Z" });

  assert.equal(result.matched, true);
  assert.equal(result.claimedHash, subjectHash);
  const slot = getSlot(db, result.claimedHash);
  assert.equal(slot.countersignatures.length, 1);
  assert.equal(slot.countersignatures[0].replay_verified, true);
  assert.equal(slot.countersignatures[0].attester_kind, "automated");

  // MC-2.3: the old code minted a counting "approval" ha_record here —
  // the exact hole §0.5 found (the daemon counted as a distinct human
  // approver). It must not exist now.
  const approvals = recordsForSubject(db, subjectHash).filter((r) => r.record_type === "approval");
  assert.equal(approvals.length, 0, "MC-2.3: an automated attestation must not mint a threshold-counting approval record");

  // signBundleDigest's output feeds this exact object shape — it must
  // conform to countersignature_slot.schema.json's `alg` enum
  // (["EdDSA", "ML-DSA-44"]), not the WebCrypto algorithm-name "Ed25519".
  const sig = slot.countersignatures[0].signature;
  const errs = validate(COUNTERSIG_SCHEMA.$defs.signature, sig, COUNTERSIG_SCHEMA);
  assert.deepEqual(errs, [], `countersignature signature must validate against countersignature_slot.schema.json: ${errs.join("; ")}`);
  db.close();
});

test("recordReplay: NEVER infers replay_verified — a mismatched re-execution records false, not true", async () => {
  const db = dbAt("replay-mismatch.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest();
  await executeRun(db, { runId: "run-replay-bad", manifest, stepRunner });

  // Tamper the recorded output IN PLACE (simulating a stored/compromised
  // claim) — a real re-execution of the SAME kernel+inputs must not agree.
  const [n1] = planSteps(manifest);
  const row = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").get("run-replay-bad", n1.step_id);
  const tampered = JSON.parse(row.output_json);
  tampered.artifact.execution_hash = "0".repeat(64);
  db.prepare("UPDATE step_results SET output_json = ? WHERE run_id = ? AND step_id = ?").run(JSON.stringify(tampered), "run-replay-bad", n1.step_id);

  const maker = await newIdentity();
  getOrInitSlot(db, `sha256:${"0".repeat(64)}`, { keyid: maker.id, sig: "probe-sig", alg: "EdDSA" });

  const checker = await newIdentity();
  const result = await recordReplay(db, { runId: "run-replay-bad", stepId: n1.step_id, checkerIdentity: checker, nowISO: "2026-07-24T13:00:00Z" });
  assert.equal(result.matched, false);
  const slot = getSlot(db, result.claimedHash);
  assert.equal(slot.countersignatures[0].replay_verified, false);
  db.close();
});

test("addCountersignature (via recordReplay): refuses a countersignature whose identity equals the slot's maker (MC-1, RED without the fix)", async () => {
  const db = dbAt("replay-same-identity.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest();
  await executeRun(db, { runId: "run-replay-selfsame", manifest, stepRunner });

  const [n1] = planSteps(manifest);
  const subjectHashHex = await runToArtifactHash("replay-same-identity-probe.db");
  const subjectHash = `sha256:${subjectHashHex}`;

  // The maker and the "checker" are the SAME did:key — exactly the hole
  // HELM-MAKERCHECKER-BUILD-SPEC.md §0.2 quotes at ha-store.mjs:135-137: the
  // old predicate compared checkers against each other only, never against
  // the maker, so one keypair satisfied both roles.
  const sameParty = await newIdentity();
  getOrInitSlot(db, subjectHash, { keyid: sameParty.id, sig: "probe-sig", alg: "EdDSA" });

  await assert.rejects(
    recordReplay(db, { runId: "run-replay-selfsame", stepId: n1.step_id, checkerIdentity: sameParty, nowISO: "2026-07-24T13:00:00Z" }),
    /same-identity countersignature forbidden/
  );
  db.close();
});

test("recordReplay: a matched automated attestation does NOT, by itself, satisfy even a review_required(1) gate (MC-2, RED without the fix)", async () => {
  const db = dbAt("replay-automated-no-gate.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest({ gatePolicy: "review_required", gateThreshold: 1 });

  const held = await executeRun(db, { runId: "run-replay-auto", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");
  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("run-replay-auto"));

  // n2's gate subject IS n1's own artifact hash (the step preceding the
  // gate) — recordReplay against n1's step_id operates on that SAME
  // subject, so a matched replay is a direct attempt to satisfy this gate.
  const maker = await newIdentity();
  getOrInitSlot(db, foundHold.subjectHash, { keyid: maker.id, sig: "probe-sig", alg: "EdDSA" });

  const [n1] = planSteps(manifest);
  const daemonChecker = await newIdentity();
  const replay = await recordReplay(db, { runId: "run-replay-auto", stepId: n1.step_id, checkerIdentity: daemonChecker, nowISO: "2026-07-24T13:00:00Z" });
  assert.equal(replay.matched, true);
  assert.equal(replay.claimedHash, foundHold.subjectHash);

  const stillHeld = await executeRun(db, { runId: "run-replay-auto", manifest, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(stillHeld.state, "awaiting_data", "MC-2: a daemon-held (automated) countersignature must never satisfy the checker threshold alone");
  db.close();
});

// §27.5 override-expiry conformance vector — mirrors validate-ha-records
// .test.mjs's override_active/override_expired fixtures (vendored, site-
// owned) at the run-engine integration level: an ACTIVE time-boxed override
// satisfies a gate with NO approval records at all; the SAME override, once
// its `nowClock` has moved past `expiry`, reverts to the underlying policy
// (never a silent permanent auto-pass) and the run holds again.
test("run engine: an active §27.5 override satisfies a held gate; after expiry it reverts to holding", async () => {
  const db = dbAt("override-expiry.db");
  const stepRunner = async (step) => runKernelNode(step, {});
  const manifest = gatedManifest({ gatePolicy: "review_required" });

  let clockNow = "2026-07-24T12:00:00Z";
  const gateCheck = haGateCheckFor(db, { nowClock: () => clockNow });

  const held = await executeRun(db, { runId: "run-override", manifest, stepRunner, gateCheck });
  assert.equal(held.state, "awaiting_data");
  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get("run-override"));

  const officer = await newIdentity();
  const override = await signHaRecord(
    {
      record_type: "override", role: "compliance_officer", subject_hash: foundHold.subjectHash, identity: { id: officer.id },
      gate_policy: "emergency_override", reason_code: "REG_DEADLINE_WAIVER",
      override: { scope: `gate:${foundHold.step_id}`, expiry: "2026-07-24T13:00:00Z", subject_hash: foundHold.subjectHash },
      timestamp: clockNow,
    },
    officer, { nowISO: clockNow }
  );
  await submitHaRecord(db, override);

  // Still within the window (12:30 < 13:00 expiry) — NO approval record
  // exists, only the override, yet the gate is satisfied.
  clockNow = "2026-07-24T12:30:00Z";
  const satisfied = await executeRun(db, { runId: "run-override", manifest, stepRunner, gateCheck });
  assert.equal(satisfied.state, "completed", "an active override must satisfy the gate with zero approval records");

  // A SECOND run against the same subject, clock moved PAST expiry — the
  // exact same override record is now inert; the gate reverts to holding
  // rather than granting a silent permanent pass.
  clockNow = "2026-07-24T14:00:00Z";
  const heldAgain = await executeRun(db, { runId: "run-override-2", manifest, stepRunner, gateCheck });
  assert.equal(heldAgain.state, "awaiting_data", "an EXPIRED override must revert to the underlying policy, never a permanent auto-pass");
  db.close();
});
