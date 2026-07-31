// BANK-NYDFS-HPACK-1 (HELM-HA-BUILD-SPEC.md §3.6): end-to-end proof of the
// chainless direct-artifact binding path over a REAL compiled pack —
// pack-bank-nydfs-annual-certification (scripts/chainless-packs.json), the
// NYDFS Part 500 annual certification's countersignature showcase.
//
// RED-BEFORE-GREEN (SO #14g doctrine): the gate is proven HOLDING at zero
// approvals AND at one, before it is proven satisfied at two — a gate never
// seen to fire is not known to work.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-nydfs-hpack-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { executeRun, planSteps } = await import("./run.mjs");
const { getPack } = await import("./packs.mjs");
const { createKernelStepRunner } = await import("./kernel-runner.mjs");
const { haGateCheckFor, findHeldGate, signHaRecord, submitHaRecord, recordArtifactBindingVerification, getSlot } = await import("./ha-gate.mjs");
const { recordsForSubject, getOrInitSlot } = await import("./ha-store.mjs");
const { rawPubkeyToDidKey } = await import("./vendored/ocg/kernels/_proof.mjs");
const { buildCommitteePackHtml } = await import("../ui/lib/committee-pack.mjs");
const { DEMO_GOLDEN_BUNDLE } = await import("../ui/fixtures/verify-demo.mjs");

const WORKFLOW_ID = "pack-bank-nydfs-annual-certification";
// Independently precomputed (scratch script over the pinned manifest_digest
// / inputs_digest / content_digest, same jcsDigestHex the runner uses) —
// asserting against a value derived OUTSIDE the runner proves the runner
// isn't just echoing back whatever it's handed.
const EXPECTED_EXECUTION_HASH = "2ee2ac5539a3d246a92598420c46435b2a361872ba1da05b37d4c7b44c119b40";

function dbAt(name) {
  return openJournal(join(TMP, name));
}

async function newIdentity() {
  const keyPair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return { id: await rawPubkeyToDidKey(keyPair.publicKey), privateKey: keyPair.privateKey };
}

test("compiled pack: pack-bank-nydfs-annual-certification carries the §3.1 attested_artifacts layer + dual_control(2) node gate", () => {
  const pack = getPack(WORKFLOW_ID);
  assert.ok(pack, "expected pack-bank-nydfs-annual-certification to have compiled — run `node scripts/compile-packs.mjs` first");
  assert.equal(pack.manifest.attested_artifacts.length, 1);
  assert.equal(pack.manifest.attested_artifacts[0].artifact_id, "nydfs-cert-2026");
  const gated = pack.manifest.nodes.find((n) => n.node_id === "n1");
  assert.equal(gated.gate_policy, "dual_control");
  assert.equal(gated.gate_role, "approver");
  assert.equal(gated.gate_threshold, 2);
});

test("run engine over the real compiled pack: attested_artifacts step executes for real (no dry-run) and derives the expected execution_hash", async () => {
  const pack = getPack(WORKFLOW_ID);
  const db = dbAt("nydfs-run-1.db");
  const runId = "nydfs-run-1";

  const held = await executeRun(db, { runId, manifest: pack.manifest, dryRun: false, stepRunner: createKernelStepRunner(), gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data", "RED: dual_control(2) with zero approvals must hold, not fall through");
  assert.equal(held.held.step_id, "nodes:n1");

  const steps = planSteps(pack.manifest);
  const attestedStep = steps.find((s) => s.step_id === "attested_artifacts:nydfs-cert-2026");
  assert.equal(attestedStep.kind, "attested_artifacts");
  const recordedRows = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").all(runId, attestedStep.step_id);
  assert.equal(recordedRows.length, 1);
  const recorded = JSON.parse(recordedRows[0].output_json);
  assert.equal(recorded.trust_label, "hash_verified");
  assert.equal(recorded.artifact.execution_hash, EXPECTED_EXECUTION_HASH, "runner-derived execution_hash must match the independently precomputed value");
  db.close();
});

test("§3.3 Tier B + maker approval: one distinct identity is NOT enough, two resumes the cert; replay_verified is never set for a chainless artifact", async () => {
  const pack = getPack(WORKFLOW_ID);
  const db = dbAt("nydfs-run-2.db");
  const runId = "nydfs-run-2";
  const stepRunner = createKernelStepRunner();

  const held = await executeRun(db, { runId, manifest: pack.manifest, dryRun: false, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(held.state, "awaiting_data");
  const foundHold = await findHeldGate(db, db.prepare("SELECT * FROM runs WHERE run_id = ?").get(runId));
  assert.equal(foundHold.gatePolicy, "dual_control");
  assert.equal(foundHold.subjectHash, `sha256:${EXPECTED_EXECUTION_HASH}`);

  // Maker: the CISO/compliance officer who produced the certification bundle
  // records their own §27.2 approval over its execution_hash.
  const maker = await newIdentity();
  const makerRecord = await signHaRecord(
    { record_type: "approval", role: "approver", subject_hash: foundHold.subjectHash, identity: { id: maker.id }, decision: "approve", reason_code: "MAKER_ATTESTATION", timestamp: "2026-07-26T12:00:00Z" },
    maker, { nowISO: "2026-07-26T12:00:00Z" }
  );
  await submitHaRecord(db, makerRecord);

  // RED still: one distinct identity is not dual_control(2).
  const stillHeld = await executeRun(db, { runId, manifest: pack.manifest, dryRun: false, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(stillHeld.state, "awaiting_data", "one approval must not satisfy dual_control(2)");

  // Checker: §3.3 Tier B binding-integrity verification — never replay,
  // never a kernel re-run.
  //
  // HELM-MAKERCHECKER-1 / MC-1.1: addCountersignature refuses unless the
  // slot already carries a maker_signature. This WU builds no maker-
  // signature producer (HELM-MAKERCHECKER-BUILD-SPEC.md §0.6) — separate
  // from, and in addition to, the maker's §27.2 approval record above —
  // so the test stands one up directly via the existing getOrInitSlot
  // capability before the checker's binding-integrity verification.
  const makerSlotKey = await newIdentity();
  getOrInitSlot(db, foundHold.subjectHash, { keyid: makerSlotKey.id, sig: "probe-sig", alg: "EdDSA" });

  const checker = await newIdentity();
  const verification = await recordArtifactBindingVerification(db, { runId, stepId: "attested_artifacts:nydfs-cert-2026", checkerIdentity: checker, nowISO: "2026-07-26T13:00:00Z" });
  assert.equal(verification.matched, true);
  assert.equal(verification.recomputedHash, EXPECTED_EXECUTION_HASH);
  assert.equal(verification.claimedHash, `sha256:${EXPECTED_EXECUTION_HASH}`);
  assert.equal(verification.slot.countersignatures.length, 1);
  assert.equal("replay_verified" in verification.slot.countersignatures[0], false, "Tier B must OMIT replay_verified — never true, never false");

  // GREEN: maker + checker are two distinct approvers.
  const resumed = await executeRun(db, { runId, manifest: pack.manifest, dryRun: false, stepRunner, gateCheck: haGateCheckFor(db) });
  assert.equal(resumed.state, "completed");

  const records = recordsForSubject(db, foundHold.subjectHash);
  const distinctApprovers = new Set(records.filter((r) => r.decision === "approve").map((r) => r.identity.id));
  assert.equal(distinctApprovers.size, 2);
  const checkerRecord = records.find((r) => r.identity.id === checker.id);
  assert.equal(checkerRecord.reason_code, "ARTIFACT_BINDING_VERIFIED");

  const slot = getSlot(db, foundHold.subjectHash);
  assert.equal(slot.countersignatures.length, 1);

  // Committee Pack export — the maker + checker records and the countersignature
  // slot flow through the SAME generic trust-labeled entries[] mechanism the
  // rest of the pack export already uses (no bespoke §27 template needed:
  // trustLabelCounts already carries "human_attested").
  const entries = [
    { kind: "attested_artifact", trust_label: "hash_verified", valid: true, digest: `sha256:${EXPECTED_EXECUTION_HASH}`, predicate: { artifact_id: "nydfs-cert-2026", step_id: "attested_artifacts:nydfs-cert-2026" } },
    { kind: "node_acceptance", trust_label: "kernel_verified", valid: true, digest: `sha256:${EXPECTED_EXECUTION_HASH}`, predicate: { node_id: "n1", step_id: "nodes:n1" } },
    ...records.map((r) => ({ kind: "ha_record", trust_label: "human_attested", valid: true, digest: r.subject_hash, predicate: { record_type: r.record_type, role: r.role, identity: r.identity.id, reason_code: r.reason_code, decision: r.decision } })),
  ];
  const html = buildCommitteePackHtml({
    bundle: DEMO_GOLDEN_BUNDLE,
    entries,
    checkpoints: [],
    manifest: pack.manifest,
    manifestDigest: pack.workflow_manifest_digest,
    generatedAt: "2026-07-26T14:00:00Z",
    meta: { entity: "Sample Covered Entity", period: "FY2026", preparer: "Sample CISO" },
  });
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /data-outcome="green"/);
  assert.match(html, /human_attested/);
  assert.match(html, /hash_verified/);
  assert.match(html, /kernel_verified/);

  db.close();
});
