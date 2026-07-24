// HELM-P3-V9 auditor PDF (print-CSS HTML) — template-only test (no crypto),
// using the same demo bundle as the Verify view.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAuditorHtml } from "./auditor-pdf.mjs";
import { DEMO_GOLDEN_BUNDLE } from "../fixtures/verify-demo.mjs";

const entries = [
  { kind: "connector_attestation", trust_label: "connector_asserted", digest: DEMO_GOLDEN_BUNDLE.manifest.predicate.entries[0].digest, envelope: DEMO_GOLDEN_BUNDLE.objects[0].envelope, predicate: { run_id: "run-verify-demo-1", connector_id: "google-drive.fetch", requested_at: "2026-07-23T00:00:00.000Z" } },
];

test("buildAuditorHtml: renders known fields, UTC timestamp note, and a QR script for the digest", () => {
  const html = buildAuditorHtml({
    bundle: DEMO_GOLDEN_BUNDLE,
    entries,
    checkpoints: [],
    manifestDigest: "sha256:" + "0".repeat(64),
    generatedAt: "2026-07-24T00:00:00.000Z",
  });
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /google-drive\.fetch/);
  assert.match(html, /\(UTC, ISO-8601\)/);
  assert.match(html, /qrcodegen\.QrCode\.encodeText/);
  assert.match(html, /@media print/);
  assert.match(html, /prefers-color-scheme: dark/);
});

test("buildAuditorHtml: omits the QR block when no manifestDigest is supplied", () => {
  const html = buildAuditorHtml({ bundle: DEMO_GOLDEN_BUNDLE, entries: [], checkpoints: [] });
  assert.doesNotMatch(html, /qrcodegen/);
});
