// HELM-H7 "done" criterion: a full round-trip fixture — drive-fetch (connector
// attestation) -> kernel (vendored NPV kernel) -> bundle (§26.7 assembler) ->
// journal (§26.5 running hash) -> checkpoint (signed, §26.5) -> anchor (live
// RFC 3161 relay, §20) — plus a TAMPERED-BUNDLE fixture proven to FAIL.
import { test } from "node:test";
import assert from "node:assert/strict";
import { liveTest } from "../test-support/live.mjs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-roundtrip-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { openJournal, replayVerify } = await import("./journal.mjs");
const { executeRun, replayExecutionHash, manifestDigest } = await import("./run.mjs");
const { pinnedKernelDigest, createKernelStepRunner } = await import("./kernel-runner.mjs");
const { buildConnectorAttestation } = await import("./connector.mjs");
const { buildCheckpoint, verifyCheckpoint } = await import("./checkpoint.mjs");
const { assembleBundle, verifyBundle } = await import("./bundle.mjs");
const { anchorRfc3161, RELAY_CA_LIST } = await import("./anchor-client.mjs");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);
const KERNEL_ID = "art-324-tvm-npv";

function manifest() {
  return {
    manifest_version: "1",
    workflow_id: "wf-h7-round-trip",
    trigger: { type: "manual" },
    connectors: [{ connector_id: "google-drive.fetch" }],
    nodes: [
      {
        node_id: "n1",
        kernel_id: KERNEL_ID,
        kernel_digest: pinnedKernelDigest(KERNEL_ID),
        policy_parameters: {
          mode: "periods",
          discount_rate_pct: 8,
          cash_flows: [{ amount: -2000, t: 0 }, { amount: 1200, t: 1 }, { amount: 1200, t: 2 }],
        },
      },
    ],
    gates: [],
    actions: [],
  };
}

liveTest("H7 round-trip: drive-fetch -> kernel -> bundle -> journal -> checkpoint -> anchor", { timeout: 40_000 }, async () => {
  const runId = "run-h7-roundtrip-1";
  const db = openJournal(join(TMP, "roundtrip.db"));

  // 1. drive-fetch stage: a connector_attestation for a (simulated, no live
  // OAuth needed in this WU's scope) file read — payload never leaves as
  // bytes, only its digest does (§26.4 connector_attestation shape).
  const wfManifest = manifest();
  const wfDigest = manifestDigest(wfManifest);
  const fakePayload = Buffer.from("fixture drive file contents");
  let attestation;
  const stepRunner = createKernelStepRunner({
    now: "2026-07-23T00:00:00.000Z",
    otherKindsRunner: async (step) => {
      assert.equal(step.kind, "connectors");
      attestation = buildConnectorAttestation({
        runId,
        workflowManifestDigest: wfDigest,
        connectorId: "google-drive.fetch",
        connectorVersion: "1.0.0",
        contractDigest: "sha256:" + "9".repeat(64),
        operation: "drive.files.get",
        scope: ["drive.readonly"],
        endpointHost: "www.googleapis.com",
        payloadBytes: fakePayload,
      });
      return { attestation };
    },
  });

  // 2. kernel stage: run engine invokes the vendored NPV kernel for n1.
  const result = await executeRun(db, { runId, manifest: wfManifest, stepRunner });
  assert.equal(result.state, "completed");
  assert.equal(replayExecutionHash(db, runId), result.executionHash);
  assert.equal(replayVerify(db).ok, true);

  const nodeStep = result.steps.find((s) => s.step_id === "nodes:n1");
  const connectorStep = result.steps.find((s) => s.step_id.startsWith("connectors:"));
  assert.ok(nodeStep && connectorStep);

  // 3. journal + checkpoint: sign a checkpoint over the current journal heads.
  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys });
  assert.equal(verifyCheckpoint(db, checkpoint, publicKeys).valid, true);

  // 4. anchor: a real RFC 3161 timestamp over the checkpoint's journal root
  // (single call — the shipped relay's rate limit is 50 req/10s, memory:
  // project-ainumbers-cloudflare-housekeeping-2026-07-11).
  const anchor = await anchorRfc3161(checkpoint.journalRootDigest.replace(/^sha256:/, ""), { ca: RELAY_CA_LIST[0] });
  assert.equal(anchor.type, "rfc3161");

  // 5. bundle: assemble the connector attestation + node step result, signed
  // and labeled, referencing the checkpoint and the anchor.
  const bundle = assembleBundle({
    bundleId: `bundle-${runId}`,
    runId,
    workflowManifestDigest: wfDigest,
    specs: [
      {
        kind: "connector_attestation",
        subject: [{ name: "payload", digest: { sha256: createHash("sha256").update(fakePayload).digest("hex") } }],
        predicate: attestation,
      },
      {
        kind: "step_result",
        subject: [{ name: "output", digest: { sha256: nodeStep.output_digest.replace(/^sha256:/, "") } }],
        predicate: { run_id: runId, step_id: nodeStep.step_id, output_digest: nodeStep.output_digest },
      },
    ],
    checkpoints: [checkpoint],
    anchorsRef: [anchor.type + ":" + anchor.ca],
    keys,
  });

  const verified = verifyBundle(bundle, publicKeys);
  assert.deepEqual(verified, { valid: true, reasons: [] });
  db.close();
});

test("TAMPERED-BUNDLE round-trip: a bundle whose checkpoint no longer matches live journal state is proven to FAIL", () => {
  const runId = "run-h7-roundtrip-tamper";
  const db = openJournal(join(TMP, "roundtrip-tamper.db"));

  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys }); // empty journal — valid but trivial
  const bundle = assembleBundle({
    bundleId: `bundle-${runId}`,
    runId,
    workflowManifestDigest: "sha256:" + "7".repeat(64),
    specs: [
      {
        kind: "step_result",
        subject: [{ name: "output", digest: { sha256: "8".repeat(64) } }],
        predicate: { run_id: runId, step_id: "nodes:n1", output_digest: "sha256:" + "8".repeat(64) },
      },
    ],
    checkpoints: [checkpoint],
    keys,
  });

  // Corrupt the checkpoint envelope directly (simplest tamper that must fail
  // both checkpoint-level and bundle-level verification).
  const tampered = structuredClone(bundle);
  tampered.checkpoints[0].envelope.signatures[0].sig = Buffer.from("not a real signature").toString("base64");

  const cpResult = verifyCheckpoint(db, tampered.checkpoints[0], publicKeys);
  assert.equal(cpResult.valid, false);

  const bundleResult = verifyBundle(tampered, publicKeys);
  assert.equal(bundleResult.valid, false);
  assert.ok(bundleResult.reasons.some((r) => r.startsWith("checkpoint_envelope_invalid")));
  db.close();
});
