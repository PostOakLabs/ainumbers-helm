// HELM-ENVELOPE-INTEGRATION-1 done-criteria: a genuinely Ed25519-signed AINumbers
// Evidence Envelope v0.1 receipt (the upstream art-652-verify-receipt kernel's own
// golden fixture — see ../ui/vendored/evidence-envelope-verify.mjs's header for the
// pin) verifies green inside a real, DSSE-sealed Helm evidence bundle, entirely
// offline (the same WebCrypto verify chain the embedded verify.html runs — see
// bundle.mjs's exportBundleZip header); a tampered copy of that same receipt FAILS.
// Additive: assembleBundle/verifyBundle for every OTHER §26.4 kind is completely
// untouched by this file or by the change it tests (see verify-bundle.test.mjs and
// bundle.test.mjs, both unmodified, for the pre-existing-bundle regression proof).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-evidence-envelope-bundle-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys } = await import("./keys.mjs");
const { assembleBundle, browserPublicKeys } = await import("./bundle.mjs");
const { verifyBundle: verifyBundleOffline, EVIDENCE_ENVELOPE_RECEIPT_KIND } = await import("../ui/lib/verify-bundle.mjs");
const { EVIDENCE_ENVELOPE_VERIFY_VECTORS } = await import("../ui/fixtures/evidence-envelope-verify-fixtures.mjs");

const keys = loadOrCreateKeys();
const publicKeys = browserPublicKeys(keys);
const RUN_ID = "run-evidence-envelope-1";
const WF_DIGEST = "sha256:" + "a".repeat(64);

function bundleWithReceipt(vectorName) {
  const vector = EVIDENCE_ENVELOPE_VERIFY_VECTORS.find((v) => v.name === vectorName);
  return assembleBundle({
    bundleId: "bundle-evidence-envelope-1",
    runId: RUN_ID,
    workflowManifestDigest: WF_DIGEST,
    specs: [
      {
        kind: EVIDENCE_ENVELOPE_RECEIPT_KIND,
        subject: [{ name: "receipt", digest: { sha256: "a".repeat(64) } }],
        predicate: { run_id: RUN_ID, receipt: vector.receipt, previous_receipt: vector.previous_receipt ?? null },
      },
    ],
    keys,
  });
}

test("a real Ed25519-signed Evidence Envelope v0.1 receipt verifies green inside a Helm evidence bundle, fully offline", async () => {
  const bundle = bundleWithReceipt("genesis-receipt-verifies");
  const result = await verifyBundleOffline(bundle, publicKeys);
  assert.equal(result.valid, true, JSON.stringify(result.reasons));
  const entry = result.detail.entries.find((e) => e.kind === EVIDENCE_ENVELOPE_RECEIPT_KIND);
  assert.equal(entry.valid, true);
  assert.equal(entry.evidence_envelope.valid, true);
  assert.ok(entry.evidence_envelope.checks.some((c) => c.code === "SIGNATURE_VALID" && c.ok === true));
});

test("a receipt with a tampered Ed25519 signature FAILS the bundle, not silently accepted", async () => {
  const bundle = bundleWithReceipt("tampered-signature-bytes-fails");
  const result = await verifyBundleOffline(bundle, publicKeys);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("entry_evidence_envelope_invalid")));
  const entry = result.detail.entries.find((e) => e.kind === EVIDENCE_ENVELOPE_RECEIPT_KIND);
  assert.equal(entry.valid, false);
  assert.equal(entry.evidence_envelope.valid, false);
  assert.ok(entry.evidence_envelope.checks.some((c) => c.code === "SIGNATURE_INVALID" && c.ok === false));
});

test("a receipt with a tampered previousReceiptHash chain link FAILS the bundle", async () => {
  const bundle = bundleWithReceipt("tampered-prev-link-mismatch");
  const result = await verifyBundleOffline(bundle, publicKeys);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("entry_evidence_envelope_invalid")));
});
