// HELM-P4-A2 committee deck spec — template-only test (no crypto, no DOM),
// same demo bundle pattern as committee-pack.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildCommitteeDeckSpec } from "./committee-deck.mjs";
import { DEMO_GOLDEN_BUNDLE } from "../fixtures/verify-demo.mjs";

const entries = [
  { kind: "connector_attestation", trust_label: "connector_asserted", valid: true, digest: DEMO_GOLDEN_BUNDLE.manifest.predicate.entries[0].digest, envelope: DEMO_GOLDEN_BUNDLE.objects[0].envelope, predicate: { run_id: "run-verify-demo-1", connector_id: "google-drive.fetch", requested_at: "2026-07-23T00:00:00.000Z" } },
];

const manifest = {
  manifest_version: "1",
  workflow_id: "wf-demo",
  trigger: { type: "manual" },
  nodes: [{ node_id: "n1", kernel_id: "k1", kernel_digest: "sha256:" + "1".repeat(64) }],
  connectors: [{ connector_id: "google-drive.fetch", contract_digest: "sha256:" + "2".repeat(64) }],
  gates: [],
  actions: [],
};

test("buildCommitteeDeckSpec: green outcome, process map attached, decision rows populated", () => {
  const spec = buildCommitteeDeckSpec({
    bundle: DEMO_GOLDEN_BUNDLE,
    entries,
    checkpoints: [],
    manifest,
    manifestDigest: "sha256:" + "0".repeat(64),
    generatedAt: "2026-07-24T00:00:00.000Z",
    meta: { entity: "Acme Corp", period: "Q2 2026", preparer: "J. Doe" },
  });
  assert.equal(spec.title.entity, "Acme Corp");
  assert.equal(spec.evidenceStatus.overallOk, true);
  assert.equal(spec.processMap.available, true);
  assert.match(spec.processMap.svg, /<svg /);
  assert.match(spec.processMap.svg, /<style>/);
  assert.equal(spec.decisionTable.rows.length, 1);
  assert.equal(spec.decisionTable.rows[0][2], "connector_asserted");
});

test("buildCommitteeDeckSpec: amber outcome on a failed check, honest process-map fallback without a manifest", () => {
  const spec = buildCommitteeDeckSpec({
    bundle: DEMO_GOLDEN_BUNDLE,
    entries: [{ ...entries[0], valid: false }],
    checkpoints: [],
    generatedAt: "2026-07-24T00:00:00.000Z",
  });
  assert.equal(spec.evidenceStatus.overallOk, false);
  assert.equal(spec.processMap.available, false);
  assert.match(spec.processMap.note, /not shown/);
  assert.equal(spec.decisionTable.rows[0][3], "✗ failed");
});

test("buildCommitteeDeckSpec: trust-label counts cover all five §26.6 labels even at zero", () => {
  const spec = buildCommitteeDeckSpec({ bundle: DEMO_GOLDEN_BUNDLE, entries: [], checkpoints: [], generatedAt: "2026-07-24T00:00:00.000Z" });
  assert.equal(spec.evidenceStatus.trustCounts.length, 5);
  assert.ok(spec.evidenceStatus.trustCounts.every((c) => c.n === 0));
});
