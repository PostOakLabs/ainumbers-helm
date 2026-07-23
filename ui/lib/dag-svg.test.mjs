import test from "node:test";
import assert from "node:assert/strict";
import { buildDag } from "./manifest-dag.mjs";
import { renderDagSvg, layoutDag } from "./dag-svg.mjs";

const manifest = {
  manifest_version: "1",
  workflow_id: "wf-test",
  trigger: { type: "schedule", schedule: "0 6 * * *" },
  nodes: [{ node_id: "n1", kernel_id: "art-213", kernel_digest: "sha256:" + "a".repeat(64) }],
  connectors: [{ connector_id: "google-drive.fetch", contract_digest: "sha256:" + "b".repeat(64) }],
  gates: [{ gate_id: "g1", type: "review" }],
  actions: [{ action_id: "a1", type: "email.notify", target_host: "smtp.example.com" }],
};

test("renderDagSvg escapes hostile labels", () => {
  const hostile = { ...manifest, actions: [{ action_id: "a1", type: "<script>alert(1)</script>", target_host: "x" }] };
  const svg = renderDagSvg(buildDag(hostile));
  assert.ok(!svg.includes("<script>alert"));
  assert.ok(svg.includes("&lt;script&gt;"));
});

test("renderDagSvg emits one dag-node group per manifest item", () => {
  const svg = renderDagSvg(buildDag(manifest));
  const count = (svg.match(/class="dag-node"/g) || []).length;
  assert.equal(count, 5); // trigger + 1 connector + 1 node + 1 gate + 1 action
});

test("layoutDag places later layers at increasing x", () => {
  const { positions } = layoutDag(buildDag(manifest));
  const triggerX = positions.get("trigger:trigger").x;
  const actionX = positions.get("actions:a1").x;
  assert.ok(actionX > triggerX);
});
