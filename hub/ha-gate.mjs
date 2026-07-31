// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// §27.4 gate-precondition wiring + §27.3 replay-verified countersigning
// (HELM-HA-1). Thin glue: the actual evaluator is vendored `_hagate.mjs`
// (single source of truth, shared with the site's own consumers) and the
// actual re-execution is `kernel-runner.mjs`'s `runKernelNode` (the SAME
// deterministic invocation the run engine itself uses) — this file adds no
// second implementation of either, it just wires HA-record storage and the
// run engine's hold/resume plumbing to them.
import { createHash } from "node:crypto";
import { didKeyToPublicKey, sign, verify } from "./vendored/ocg/kernels/_proof.mjs";
import { evaluateHaGate } from "./vendored/ocg/kernels/_hagate.mjs";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { recordsForSubject, appendHaRecord, addCountersignature, getSlot } from "./ha-store.mjs";
import { runKernelNode } from "./kernel-runner.mjs";
import { planSteps, getMemoizedStep, stepInputDigest } from "./run.mjs";

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

// Signs an unsigned §27.2 record with the given identity (either helmd's own
// ha-identity.mjs keypair, or a caller-supplied one in tests) — the ONE path
// that mints `audit_signature.proof`, reused for every helmd-authored record
// (role_binding, and the approval this module appends after a verified
// replay). A browser-signed human approval never passes through this
// function; it arrives at ha-store.mjs already signed and is verified, not
// re-signed, by verifyHaRecordSignature below.
export async function signHaRecord(record, identity, { nowISO } = {}) {
  return sign(record, {
    verificationMethod: `${identity.id}#key-1`,
    created: nowISO ?? new Date().toISOString(),
    privateKey: identity.privateKey,
  });
}

// Cryptographic (not just structural) verification: resolves the acting
// party's public key from their OWN identity.id (did:key is self-certifying
// — no registration/pairing step needed for helmd to check a browser-signed
// approval it has never seen before) and checks the §16 signature over the
// record. This is the gate every record MUST pass before appendHaRecord.
export async function verifyHaRecordSignature(record) {
  const proof = record?.audit_signature?.proof;
  if (!proof?.verificationMethod?.startsWith(record?.identity?.id ?? "\0")) return false;
  const did = record.identity.id;
  try {
    const publicKey = await didKeyToPublicKey(did);
    return await verify(record, publicKey);
  } catch {
    return false;
  }
}

// Verifies + stores in one call — the path every REST-submitted record
// (POST /ha/records) goes through. Throws (never silently drops) on a bad
// signature or a shape the store refuses.
export async function submitHaRecord(db, record) {
  const cryptoOk = await verifyHaRecordSignature(record);
  if (!cryptoOk) throw new Error("ha-gate: record signature does not verify against its own identity.id — refused");
  return appendHaRecord(db, record);
}

// gateCheck callback shape run.mjs's executeRun expects: given a "nodes"
// step whose item declares `gate_policy` (the §1 item-5 additive pack
// field), evaluate §27.4 against the records collected so far for the
// PRECEDING step's output. The subject a human is asked to approve is the
// OCG artifact's OWN execution_hash (per schema: "the execution_hash of the
// artifact being acted upon"), not helm's internal step-memo digest — so
// this prefers priorOutput.artifact.execution_hash (a "nodes" step's shape,
// see kernel-runner.mjs) and only falls back to priorOutputDigest for a
// non-kernel prior step (connectors/gates/actions have no artifact yet).
function subjectHashFor(priorOutputDigest, priorOutput) {
  const artifactHash = priorOutput?.artifact?.execution_hash;
  if (artifactHash) return `sha256:${artifactHash}`;
  return priorOutputDigest ?? `sha256:${"0".repeat(64)}`;
}

// nowClock: caller-overridable clock (defaults to the real wall clock in
// production) — §27.5 override-expiry is time-dependent, so conformance
// tests need to move "now" without an actual multi-hour sleep.
export function haGateCheckFor(db, { nowClock = () => new Date().toISOString() } = {}) {
  return async function gateCheck(step, { priorOutputDigest, priorOutput, runId }) {
    const gatePolicy = step.item?.gate_policy;
    if (!gatePolicy) return { held: false };
    const role = step.item?.gate_role ?? "approver";
    const threshold = step.item?.gate_threshold;
    const subjectHash = subjectHashFor(priorOutputDigest, priorOutput);
    const records = recordsForSubject(db, subjectHash);
    const result = evaluateHaGate({
      gatePolicy, threshold, role, subjectHash, records, nowISO: nowClock(),
    });
    if (result.status === "satisfied" || result.status === "override_active") return { held: false, gateResult: result };
    return { held: true, step_id: step.step_id, reason: `${step.step_id}: ${result.reason}`, gateResult: result, subjectHash, role, gatePolicy, threshold };
  };
}

// Scans every "nodes" step of a run currently `awaiting_data` and reports
// which one is actually holding (recomputes the SAME gateCheck the engine
// itself will re-run on resume, so the UI queue and the engine can never
// disagree about what's pending). Returns null if the run isn't at a gate
// hold (e.g. genuinely awaiting external data, or not held at all).
export async function findHeldGate(db, run) {
  const manifest = JSON.parse(run.manifest_json);
  const steps = planSteps(manifest);
  const gateCheck = haGateCheckFor(db);
  let priorOutputDigest = null;
  let priorOutput = null;
  let priorStepId = null;
  for (const step of steps) {
    const inputDigest = stepInputDigest({ runId: run.run_id, step, priorOutputDigest, dryRun: !!run.dry_run });
    const memo = getMemoizedStep(db, { runId: run.run_id, stepId: step.step_id, inputDigest });
    if (memo) { priorOutputDigest = memo.outputDigest; priorOutput = memo.output; priorStepId = step.step_id; continue; }
    const gate = await gateCheck(step, { priorOutputDigest, priorOutput, runId: run.run_id });
    // precedingStepId: the step whose OWN artifact is the subject being
    // approved — a caller (e.g. the Review UI's "Replay-verify" action)
    // re-executes THIS step, never the held one (which hasn't run yet).
    return gate.held ? { run_id: run.run_id, precedingStepId: priorStepId, ...gate } : null;
  }
  return null;
}

// §27.3 replay-verified countersigning — the Helm-only differentiator this
// row exists to ship. Re-invokes the SAME deterministic kernel node the run
// engine already ran (execution_hash's preimage excludes `generated_at`, so
// re-running with a fresh timestamp yields a byte-identical hash iff the
// inputs truly reproduce it — this is a REAL re-execution, not a stored-hash
// comparison). `replay_verified` is set true ONLY here, and ONLY when the
// freshly-recomputed hash matches what was recorded — never inferred, never
// trusted from caller input.
export async function recordReplay(db, { runId, stepId, checkerIdentity, nowISO }) {
  const runRow = db.prepare("SELECT manifest_json, dry_run FROM runs WHERE run_id = ?").get(runId);
  if (!runRow) throw new Error(`ha-gate: unknown run_id ${runId}`);
  const manifest = JSON.parse(runRow.manifest_json);
  const steps = planSteps(manifest);
  const step = steps.find((s) => s.step_id === stepId);
  if (!step) throw new Error(`ha-gate: unknown step_id ${stepId} for run ${runId}`);
  if (step.kind !== "nodes") throw new Error(`ha-gate: replay is only defined for "nodes" steps (got kind="${step.kind}")`);

  const recordedRows = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").all(runId, stepId);
  if (!recordedRows.length) throw new Error(`ha-gate: no recorded output for run=${runId} step=${stepId} — nothing to replay against`);
  const recorded = JSON.parse(recordedRows[recordedRows.length - 1].output_json);
  const claimedHashHex = recorded?.artifact?.execution_hash;
  if (!claimedHashHex) throw new Error(`ha-gate: recorded step output carries no artifact.execution_hash — cannot replay-verify`);
  const claimedHash = `sha256:${claimedHashHex}`;

  const fresh = await runKernelNode(step, {});
  const matched = fresh.artifact.execution_hash === claimedHashHex;

  const now = nowISO ?? new Date().toISOString();
  const signature = await signBundleDigest(checkerIdentity, claimedHash);
  const countersignature = {
    role: "checker",
    identity: { id: checkerIdentity.id },
    signature,
    signed_at: now,
    replay_verified: matched,
    // MC-2.1/MC-2.4 (HELM-MAKERCHECKER-BUILD-SPEC.md): the re-execution
    // above ALWAYS runs inside helmd itself (runKernelNode), regardless of
    // who triggered it — the signing key here is, by MC-2.4's definition,
    // daemon-held for as long as helmd can use it without a person present.
    // Never inferred from checkerIdentity — this function IS the automated
    // path.
    attester_kind: "automated",
  };
  const slot = addCountersignature(db, claimedHash, countersignature);

  // MC-2.3: an `automated` attestation MUST NOT mint a threshold-counting
  // approval record. Previously this minted one unconditionally on a match,
  // which is the exact hole HELM-MAKERCHECKER-BUILD-SPEC.md §0.5 found:
  // evaluateHaGate's distinctApprovers (reads ha_records, not the
  // countersignature slot) counted the daemon as one of the N distinct
  // humans a dual_control(2)/review_required gate demands. A matched replay
  // stays valuable, retained, readable evidence in the slot — it just never
  // by itself satisfies a human-accountability gate.

  return { matched, claimedHash, recomputedHash: fresh.artifact.execution_hash, slot };
}

// §3.3 Tier B — chainless attested-artifact binding verification
// (BANK-NYDFS-HPACK-1, HELM-HA-BUILD-SPEC.md §3.3). Distinct from
// recordReplay (Tier A) on purpose: a browser tool artifact has no kernel to
// re-invoke, so this NEVER sets replay_verified — omission is the honest
// state (schema-optional; `false` would falsely claim "replay attempted and
// failed", `true` would falsely claim kernel re-execution). What IS checked,
// offline and deterministically: the three pinned digests recompute the
// SAME execution_hash the maker's step recorded — a binding-integrity
// check, proof the artifact is the one the maker signed from a pinned tool
// version, NOT a recomputation of the tool's arithmetic.
export async function recordArtifactBindingVerification(db, { runId, stepId, checkerIdentity, nowISO }) {
  const runRow = db.prepare("SELECT manifest_json, dry_run FROM runs WHERE run_id = ?").get(runId);
  if (!runRow) throw new Error(`ha-gate: unknown run_id ${runId}`);
  const manifest = JSON.parse(runRow.manifest_json);
  const steps = planSteps(manifest);
  const step = steps.find((s) => s.step_id === stepId);
  if (!step) throw new Error(`ha-gate: unknown step_id ${stepId} for run ${runId}`);
  if (step.kind !== "attested_artifacts") {
    throw new Error(`ha-gate: artifact-binding verification is only defined for "attested_artifacts" steps (got kind="${step.kind}")`);
  }

  const recordedRows = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").all(runId, stepId);
  if (!recordedRows.length) throw new Error(`ha-gate: no recorded output for run=${runId} step=${stepId} — nothing to verify against`);
  const recorded = JSON.parse(recordedRows[recordedRows.length - 1].output_json);
  const claimedHashHex = recorded?.artifact?.execution_hash;
  if (!claimedHashHex) throw new Error(`ha-gate: recorded step output carries no artifact.execution_hash — cannot verify`);
  const claimedHash = `sha256:${claimedHashHex}`;

  const { tool_ref, inputs_digest, artifact } = step.item;
  const recomputedHashHex = jcsDigestHex({ tool_ref, inputs_digest, artifact: { content_type: artifact.content_type, content_digest: artifact.content_digest } });
  const matched = recomputedHashHex === claimedHashHex;

  const now = nowISO ?? new Date().toISOString();
  const signature = await signBundleDigest(checkerIdentity, claimedHash);
  const countersignature = {
    role: "checker",
    identity: { id: checkerIdentity.id },
    signature,
    signed_at: now,
    // ⛔ replay_verified deliberately OMITTED — see comment above.
    //
    // MC-2 scope note: unlike recordReplay, this function has no production
    // route wiring it to helmd's own identity (grep confirms no server.mjs
    // caller) — §0.4/§0.5's "100% of production checkers are daemon-signed"
    // finding is specific to POST /ha/replay, not this Tier-B path. Absent
    // that evidence, attester_kind is left unasserted here rather than
    // guessed; MC-2's daemon-only refusal is enforced where it was
    // actually measured (recordReplay below). Determining this path's real
    // custody model, if it needs one, is a separate, later decision.
  };
  const slot = addCountersignature(db, claimedHash, countersignature);

  if (matched) {
    const approval = await signHaRecord(
      {
        record_type: "approval",
        role: "approver",
        subject_hash: claimedHash,
        identity: { id: checkerIdentity.id },
        decision: "approve",
        reason_code: "ARTIFACT_BINDING_VERIFIED",
        timestamp: now,
      },
      checkerIdentity,
      { nowISO: now }
    );
    appendHaRecord(db, approval);
  }

  return { matched, claimedHash, recomputedHash: recomputedHashHex, slot };
}

async function signBundleDigest(identity, bundleDigest) {
  const sig = await globalThis.crypto.subtle.sign("Ed25519", identity.privateKey, Buffer.from(bundleDigest, "utf8"));
  return { keyid: identity.id, sig: Buffer.from(sig).toString("base64"), alg: "EdDSA" };
}

export { getSlot };
