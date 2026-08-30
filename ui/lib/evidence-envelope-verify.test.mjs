// HELM-ENVELOPE-INTEGRATION-1: proves ../vendored/evidence-envelope-verify.mjs (ported
// from the site's art-652-verify-receipt kernel, see that file's header for the pin)
// agrees check-for-check with the upstream kernel's own golden fixtures — the genesis
// signed receipt verifies, and each of the upstream kernel's own tamper vectors
// (bad signature bytes, a tampered payload field, an unresolvable kid, a broken
// previousReceiptHash chain link) fails the same way here that it fails upstream.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyEvidenceEnvelopeReceipt } from "../vendored/evidence-envelope-verify.mjs";
import { EVIDENCE_ENVELOPE_VERIFY_VECTORS } from "../fixtures/evidence-envelope-verify-fixtures.mjs";

for (const vector of EVIDENCE_ENVELOPE_VERIFY_VECTORS) {
  test(`evidence-envelope-verify: ${vector.name}`, async () => {
    const { valid, checks } = await verifyEvidenceEnvelopeReceipt(vector.receipt, vector.previous_receipt);
    assert.equal(valid, vector.expected.valid, `checks: ${JSON.stringify(checks)}`);
    assert.deepEqual(checks.map((c) => c.code), vector.expected.codes);
  });
}

test("evidence-envelope-verify: a real signed receipt verifies green with a fully quoted verdict", async () => {
  const genesis = EVIDENCE_ENVELOPE_VERIFY_VECTORS.find((v) => v.name === "genesis-receipt-verifies");
  const result = await verifyEvidenceEnvelopeReceipt(genesis.receipt, genesis.previous_receipt);
  assert.equal(result.valid, true);
  assert.ok(result.checks.some((c) => c.code === "SIGNATURE_VALID" && c.ok === true));
});

test("evidence-envelope-verify: a tampered signature FAILS, not just returns falsy", async () => {
  const tampered = EVIDENCE_ENVELOPE_VERIFY_VECTORS.find((v) => v.name === "tampered-signature-bytes-fails");
  const result = await verifyEvidenceEnvelopeReceipt(tampered.receipt, tampered.previous_receipt);
  assert.equal(result.valid, false);
  const sigCheck = result.checks.find((c) => c.code === "SIGNATURE_INVALID");
  assert.ok(sigCheck && sigCheck.ok === false, `expected an explicit SIGNATURE_INVALID failure, got: ${JSON.stringify(result.checks)}`);
});
