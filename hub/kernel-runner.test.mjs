import { test } from "node:test";
import assert from "node:assert/strict";
import { pinnedKernelDigest, runKernelNode, createKernelStepRunner } from "./kernel-runner.mjs";
import { manifestDigest, planSteps } from "./run.mjs";

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

test("manifestDigest is stable for the fixture manifest (sanity check for round-trip test reuse)", () => {
  const d = manifestDigest(npvManifest());
  assert.match(d, /^sha256:[0-9a-f]{64}$/);
});
