// HELM-P4-A1 Committee Pack (print-CSS HTML) — template-only test (no
// crypto), same demo bundle pattern as auditor-pdf.test.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildCommitteePackHtml } from "./committee-pack.mjs";
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

test("buildCommitteePackHtml: green banner, headline numbers, and process map when manifest attached", () => {
  const html = buildCommitteePackHtml({
    bundle: DEMO_GOLDEN_BUNDLE,
    entries,
    checkpoints: [],
    manifest,
    manifestDigest: "sha256:" + "0".repeat(64),
    generatedAt: "2026-07-24T00:00:00.000Z",
    meta: { entity: "Acme Corp", period: "Q2 2026", preparer: "J. Doe" },
  });
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /Committee Pack/);
  assert.match(html, /data-outcome="green"/);
  assert.match(html, /Acme Corp/);
  assert.match(html, /<svg /);
  assert.match(html, /steps recorded/);
  assert.match(html, /@media print/);
  assert.doesNotMatch(html, /Process map not shown/);
});

test("buildCommitteePackHtml: amber banner on a failed check, and honest process-map fallback without a manifest", () => {
  const html = buildCommitteePackHtml({
    bundle: DEMO_GOLDEN_BUNDLE,
    entries: [{ ...entries[0], valid: false }],
    checkpoints: [],
    generatedAt: "2026-07-24T00:00:00.000Z",
  });
  assert.match(html, /data-outcome="amber"/);
  assert.match(html, /Process map not shown/);
  assert.match(html, /Art\.12 journal not attached/);
});

test("buildCommitteePackHtml: zero dev chrome — no raw JSON above the appendix boundary", () => {
  const html = buildCommitteePackHtml({ bundle: DEMO_GOLDEN_BUNDLE, entries, checkpoints: [], generatedAt: "2026-07-24T00:00:00.000Z" });
  const appendixStart = html.indexOf('class="cp-appendix"');
  const beforeAppendix = html.slice(0, appendixStart);
  assert.doesNotMatch(beforeAppendix, /\{"kind"/);
});
