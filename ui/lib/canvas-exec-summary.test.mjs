import { test } from "node:test";
import assert from "node:assert/strict";
import { buildExecSummary, unverifiedSteps } from "./canvas-exec-summary.mjs";
import { buildDag } from "./manifest-dag.mjs";

const MANIFEST = {
  workflow_id: "wf-exec-summary-test",
  trigger: { trigger_id: "t1" },
  connectors: [{ connector_id: "c1" }, { connector_id: "c2" }],
  nodes: [{ node_id: "n1" }],
  gates: [{ gate_id: "g1" }],
  actions: [{ action_id: "a1" }],
};

test("buildExecSummary: three headline numbers derived from the dag, never fabricated", () => {
  const dag = buildDag(MANIFEST);
  const summary = buildExecSummary(MANIFEST, dag, "sha256:deadbeef");
  assert.equal(summary.headline.length, 3);
  assert.deepEqual(summary.headline.map((h) => h.value), [6, 2, 1]);
});

test("buildExecSummary: every check is green and carries the real digest, no run outcome claimed", () => {
  const dag = buildDag(MANIFEST);
  const summary = buildExecSummary(MANIFEST, dag, "sha256:deadbeef");
  assert.ok(summary.checks.every((c) => c.ok === true));
  assert.ok(summary.checks[0].label.includes("sha256:deadbeef"));
  assert.match(summary.runNote, /No run has been recorded/);
});

test("unverifiedSteps: PACK-MARKER — names verified:false nodes by tool_id (kernel_id), never a percentage", () => {
  const manifest = {
    ...MANIFEST,
    nodes: [
      { node_id: "n1", kernel_id: "152-baas-provider-comparator", kernel_digest: "sha256:" + "0".repeat(64), verified: false },
      { node_id: "n2", kernel_id: "art-108" },
    ],
  };
  const dag = buildDag(manifest);
  const steps = unverifiedSteps(manifest);
  assert.deepEqual(steps, [{ nodeId: "n1", toolId: "152-baas-provider-comparator" }]);

  const summary = buildExecSummary(manifest, dag, "sha256:deadbeef");
  assert.deepEqual(summary.unverified, steps);
  const badCheck = summary.checks.find((c) => c.ok === false);
  assert.ok(badCheck, "expected a non-ok check for the unverified step");
  assert.match(badCheck.label, /152-baas-provider-comparator/);
  assert.doesNotMatch(badCheck.label, /%/);
});

test("buildExecSummary: no verified:false nodes → unverified empty, all checks stay ok", () => {
  const dag = buildDag(MANIFEST);
  const summary = buildExecSummary(MANIFEST, dag, "sha256:deadbeef");
  assert.deepEqual(summary.unverified, []);
});

test("buildExecSummary: zero-count layers report zero, not omitted", () => {
  const bare = { workflow_id: "wf-bare", trigger: { trigger_id: "t1" }, actions: [{ action_id: "a1" }] };
  const dag = buildDag(bare);
  const summary = buildExecSummary(bare, dag, "sha256:cafef00d");
  assert.deepEqual(summary.headline.map((h) => h.value), [2, 0, 0]);
});
