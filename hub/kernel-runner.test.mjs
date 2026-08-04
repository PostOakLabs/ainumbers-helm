import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { pinnedKernelDigest, runKernelNode, createKernelStepRunner } from "./kernel-runner.mjs";
import { manifestDigest, planSteps, executeRun } from "./run.mjs";
import { openJournal } from "./journal.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

const TMP = mkdtempSync(join(tmpdir(), "helm-kernel-runner-test-"));

const KERNEL_ID = "art-324-tvm-npv";

function npvManifest(overrides = {}) {
  return {
    manifest_version: "1",
    workflow_id: "wf-npv-test",
    trigger: { type: "manual" },
    connectors: [],
    nodes: [
      {
        node_id: "n1",
        kernel_id: KERNEL_ID,
        kernel_digest: pinnedKernelDigest(KERNEL_ID),
        policy_parameters: {
          mode: "periods",
          discount_rate_pct: 10,
          cash_flows: [{ amount: -1000, t: 0 }, { amount: 600, t: 1 }, { amount: 600, t: 2 }],
        },
        ...overrides,
      },
    ],
    gates: [],
    actions: [],
  };
}

test("pinnedKernelDigest: returns a stable sha256ref for a real vendored kernel", () => {
  const d = pinnedKernelDigest(KERNEL_ID);
  assert.match(d, /^sha256:[0-9a-f]{64}$/);
  assert.equal(pinnedKernelDigest(KERNEL_ID), d);
});

test("pinnedKernelDigest: throws for an unknown kernel_id", () => {
  assert.throws(() => pinnedKernelDigest("not-a-real-kernel"), /unknown kernel_id/);
});

test("runKernelNode: invokes the vendored kernel and returns a kernel_verified result", async () => {
  const manifest = npvManifest();
  const [step] = planSteps(manifest);
  const result = await runKernelNode(step, { now: "2026-07-23T00:00:00.000Z" });

  assert.equal(result.trust_label, "kernel_verified");
  assert.equal(result.kernel_id, KERNEL_ID);
  assert.equal(result.artifact.tool_id, KERNEL_ID);
  assert.match(result.artifact.execution_hash, /^[0-9a-f]{64}$/);
  assert.equal(typeof result.artifact.output_payload.npv, "number");
  assert.equal(result.compute_proof_verified, null);
});

test("runKernelNode: rejects a manifest node whose kernel_digest doesn't match the vendored file", async () => {
  const manifest = npvManifest({ kernel_digest: "sha256:" + "0".repeat(64) });
  const [step] = planSteps(manifest);
  await assert.rejects(runKernelNode(step), /kernel_digest mismatch/);
});

test("runKernelNode: rejects an unknown kernel_id", async () => {
  const manifest = npvManifest({ kernel_id: "not-a-real-kernel", kernel_digest: "sha256:" + "0".repeat(64) });
  const [step] = planSteps(manifest);
  await assert.rejects(runKernelNode(step), /not found in vendored registry/);
});

test("createKernelStepRunner: dispatches nodes to the kernel and delegates other kinds", async () => {
  const otherCalls = [];
  const stepRunner = createKernelStepRunner({
    otherKindsRunner: async (step) => { otherCalls.push(step.step_id); return { ok: true }; },
    now: "2026-07-23T00:00:00.000Z",
  });

  const manifest = npvManifest();
  manifest.connectors = [{ connector_id: "c1" }];
  const steps = planSteps(manifest);

  const nodeResult = await stepRunner(steps.find((s) => s.kind === "nodes"), {});
  assert.equal(nodeResult.trust_label, "kernel_verified");

  const connectorResult = await stepRunner(steps.find((s) => s.kind === "connectors"), {});
  assert.deepEqual(connectorResult, { ok: true });
  assert.deepEqual(otherCalls, ["connectors:c1"]);
});

test("createKernelStepRunner: throws for an unhandled kind with no otherKindsRunner configured", async () => {
  const stepRunner = createKernelStepRunner();
  const manifest = npvManifest();
  manifest.gates = [{ gate_id: "g1" }];
  const steps = planSteps(manifest);
  await assert.rejects(stepRunner(steps.find((s) => s.kind === "gates"), {}), /no runner configured/);
});

test("HELM-DRYRUN-PARITY-1: dry-run and real run agree — both throw for an unhandled kind", async () => {
  const manifest = npvManifest();
  manifest.gates = [{ gate_id: "g1" }];
  const stepRunner = createKernelStepRunner();

  const db = openJournal(join(TMP, "parity.db"));
  await assert.rejects(
    executeRun(db, { runId: "run-dryrun-parity-real", manifest, stepRunner, dryRun: false }),
    /no runner configured for step kind "gates"/
  );
  await assert.rejects(
    executeRun(db, { runId: "run-dryrun-parity-dry", manifest, stepRunner, dryRun: true }),
    /no runner configured for step kind "gates"/
  );
  db.close();
});

test("HELM-DRYRUN-PARITY-1: dry-run still performs no side effects for a runnable kind", async () => {
  const manifest = npvManifest();
  const stepRunner = createKernelStepRunner();

  const db = openJournal(join(TMP, "parity-noop.db"));
  const result = await executeRun(db, { runId: "run-dryrun-parity-noop", manifest, stepRunner, dryRun: true });
  assert.equal(result.state, "completed");
  assert.equal(result.dryRun, true);
  db.close();
});

test("manifestDigest is stable for the fixture manifest (sanity check for round-trip test reuse)", () => {
  const d = manifestDigest(npvManifest());
  assert.match(d, /^sha256:[0-9a-f]{64}$/);
});

// ---------------------------------------------------------------------------
// HELM-BIND-2 (§3.1): a bound step's resolved value reaches buildArtifact via
// step.resolvedParams, overriding the node's static policy_parameters for
// just the bound feeds_param key.
// ---------------------------------------------------------------------------

test("runKernelNode: step.resolvedParams overrides policy_parameters for the bound key and changes the artifact", async () => {
  const manifest = npvManifest();
  const [step] = planSteps(manifest);

  const baseline = await runKernelNode(step, { now: "2026-07-23T00:00:00.000Z" });

  const bound = { ...step, resolvedParams: { discount_rate_pct: 50 } };
  const overridden = await runKernelNode(bound, { now: "2026-07-23T00:00:00.000Z" });

  assert.notEqual(overridden.artifact.output_payload.npv, baseline.artifact.output_payload.npv);
  assert.notEqual(overridden.artifact.execution_hash, baseline.artifact.execution_hash);
});

test("runKernelNode: no resolvedParams (unbound step) is byte-identical to today's `?? {}` behaviour", async () => {
  const manifest = npvManifest();
  const [step] = planSteps(manifest);
  assert.equal(step.resolvedParams, undefined);
  const result = await runKernelNode(step, { now: "2026-07-23T00:00:00.000Z" });
  assert.equal(result.artifact.output_payload.npv, (await runKernelNode({ ...step }, { now: "2026-07-23T00:00:00.000Z" })).artifact.output_payload.npv);
});

// ---------------------------------------------------------------------------
// PACK-MARKER-RUNNER-1 (§5): a node carrying `verified: false` is skipped —
// never a kernel_digest lookup, never executed, never `kernel_verified`.
// ---------------------------------------------------------------------------

test("runKernelNode: verified:false node is skipped-by-design, never resolves kernel_digest, never claims kernel_verified", async () => {
  const manifest = npvManifest({
    kernel_id: "152-baas-provider-comparator", // not in the vendored registry at all
    kernel_digest: "sha256:" + "0".repeat(64), // §4.4 sentinel — would never resolve
    verified: false,
  });
  const [step] = planSteps(manifest);
  const result = await runKernelNode(step, { now: "2026-07-23T00:00:00.000Z" });

  assert.equal(result.execution_state, "skipped_by_design");
  assert.equal(result.node_id, "n1");
  assert.equal(result.kernel_id, "152-baas-provider-comparator");
  assert.equal(result.trust_label, undefined, "no §26.6 trust_label — 'skipped' isn't one of the 5 closed values");
  assert.equal(result.artifact, undefined);
});

test("createKernelStepRunner: dispatches a verified:false node to the skip path, not the kernel", async () => {
  const stepRunner = createKernelStepRunner({ now: "2026-07-23T00:00:00.000Z" });
  const manifest = npvManifest({ kernel_id: "not-a-real-kernel", kernel_digest: "sha256:" + "0".repeat(64), verified: false });
  const [step] = planSteps(manifest);
  const result = await stepRunner(step, {});
  assert.equal(result.execution_state, "skipped_by_design");
});

test("PACK-MARKER-RUNNER-1: a real run against the compiled BaaS pilot pack skips every marked node, completes, never marks a skipped node completed", async () => {
  const pack = JSON.parse(readFileSync(join(HERE, "..", "packs", "pack-baas-programme.json"), "utf8"));
  const manifest = pack.manifest;
  assert.ok(manifest.nodes.every((n) => n.verified === false), "fixture sanity: every node in this pilot pack is marked");

  const stepRunner = createKernelStepRunner({ now: "2026-07-23T00:00:00.000Z" });
  const db = openJournal(join(TMP, "pack-marker-runner.db"));
  const result = await executeRun(db, { runId: "run-pack-marker-baas", manifest, stepRunner, dryRun: false });

  assert.equal(result.state, "completed"); // the RUN completes — its terminal state is unrelated to any single node's execution
  assert.equal(result.steps.length, manifest.nodes.length);

  for (const n of manifest.nodes) {
    const row = db
      .prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?")
      .get("run-pack-marker-baas", `nodes:${n.node_id}`);
    assert.ok(row, `no step_results row recorded for skipped node ${n.node_id}`);
    const output = JSON.parse(row.output_json);
    assert.equal(output.execution_state, "skipped_by_design");
    assert.notEqual(output.execution_state, "completed");
    assert.equal(output.trust_label, undefined);
  }
  db.close();
});
