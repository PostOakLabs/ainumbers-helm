import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-bundle-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { assembleBundle, verifyBundle, sealBundleObject, REDACTION_PROFILE } = await import("./bundle.mjs");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);

const RUN_ID = "run-bundle-1";
const WF_DIGEST = "sha256:" + "c".repeat(64);

function fixtureSpecs() {
  return [
    {
      kind: "connector_attestation",
      subject: [{ name: "payload", digest: { sha256: "d".repeat(64) } }],
      predicate: {
        run_id: RUN_ID,
        workflow_manifest_digest: WF_DIGEST,
        connector_id: "google-drive.fetch",
        payload_digest: "sha256:" + "d".repeat(64),
      },
    },
    {
      kind: "step_result",
      subject: [{ name: "execution_hash", digest: { sha256: "e".repeat(64) } }],
      predicate: { run_id: RUN_ID, step_id: "nodes:n1", output_digest: "sha256:" + "e".repeat(64) },
    },
  ];
}

test("assembleBundle: builds a schema-valid, signed manifest referencing every sealed object", () => {
  const bundle = assembleBundle({
    bundleId: "bundle-1",
    runId: RUN_ID,
    workflowManifestDigest: WF_DIGEST,
    specs: fixtureSpecs(),
    keys,
  });

  assert.equal(bundle.manifest.predicate.redaction_profile, REDACTION_PROFILE);
  assert.equal(bundle.manifest.predicate.entries.length, 2);
  assert.equal(bundle.objects.length, 2);
  const kinds = bundle.manifest.predicate.entries.map((e) => e.kind).sort();
  assert.deepEqual(kinds, ["connector_attestation", "step_result"]);

  const trustLabels = new Set(bundle.manifest.predicate.entries.map((e) => e.trust_label));
  assert.ok(trustLabels.has("connector_asserted"));
  assert.ok(trustLabels.has("kernel_verified"));
});

test("assembleBundle: rejects a predicate carrying a forbidden secret-shaped field", () => {
  const specs = fixtureSpecs();
  specs[0].predicate.access_token = "leaked";
  assert.throws(
    () => assembleBundle({ bundleId: "bundle-2", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs, keys }),
    /default redaction violated/
  );
});

test("verifyBundle: a golden bundle verifies clean with zero reasons", () => {
  const bundle = assembleBundle({
    bundleId: "bundle-3", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys,
  });
  const result = verifyBundle(bundle, publicKeys);
  assert.deepEqual(result, { valid: true, reasons: [] });
});

test("TAMPERED-BUNDLE: a mutated object predicate is proven to FAIL verification", () => {
  const bundle = assembleBundle({
    bundleId: "bundle-4", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys,
  });
  // Tamper: swap the DSSE payload of one sealed object for a different, still
  // well-formed statement — the signature no longer covers this payload.
  const tampered = structuredClone(bundle);
  const targetObj = tampered.objects[0];
  const forged = sealBundleObject(
    { kind: targetObj.kind, subject: [{ name: "x", digest: { sha256: "f".repeat(64) } }], predicate: { forged: true }, trustLabel: targetObj.trust_label },
    keys
  );
  targetObj.envelope.payload = forged.envelope.payload; // keep old signatures, swap payload underneath them

  const result = verifyBundle(tampered, publicKeys);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("entry_envelope_invalid") || r.startsWith("entry_digest_mismatch")));
});

test("TAMPERED-BUNDLE: a manifest entry trust_label edited post-signing is proven to FAIL", () => {
  const bundle = assembleBundle({
    bundleId: "bundle-5", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys,
  });
  const tampered = structuredClone(bundle);
  tampered.manifest.predicate.entries[0].trust_label = "human_attested"; // downgrade/relabel attempt

  const result = verifyBundle(tampered, publicKeys);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.includes("manifest_predicate_mismatch"));
});

test("TAMPERED-BUNDLE: a checkpoint the manifest references but that never verifies is proven to FAIL", () => {
  const bundle = assembleBundle({
    bundleId: "bundle-6", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys,
  });
  // Attach a bogus checkpoint claimed by the manifest but never actually signed correctly.
  const bogusEnvelope = { ...bundle.manifest.envelope, signatures: bundle.manifest.envelope.signatures.map((s) => ({ ...s, sig: "AAAA" })) };
  const tampered = structuredClone(bundle);
  tampered.checkpoints = [{ checkpointSeq: 1, journalRootDigest: "sha256:" + "1".repeat(64), envelope: bogusEnvelope }];
  tampered.manifest.predicate.checkpoints_ref = ["sha256:" + "2".repeat(64)];

  const result = verifyBundle(tampered, publicKeys);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("checkpoint_missing") || r.startsWith("checkpoint_envelope_invalid") || r === "manifest_predicate_mismatch"));
});

test("assembleBundle: presenter (HELM-P4-J2) rides along as an unsigned sibling field, invisible to verifyBundle()", () => {
  const bundle = assembleBundle({
    bundleId: "bundle-7", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys,
    presenter: { name: "Acme Bank Compliance", statement: "Reviewed by Acme Bank." },
  });
  assert.deepEqual(bundle.presenter, { name: "Acme Bank Compliance", statement: "Reviewed by Acme Bank." });
  assert.equal(bundle.manifest.predicate.presenter, undefined, "presenter must never enter the signed manifest predicate");

  const swapped = { ...bundle, presenter: { name: "A Different Reseller Entirely" } };
  const result = verifyBundle(swapped, publicKeys);
  assert.deepEqual(result, { valid: true, reasons: [] });
});

test("assembleBundle: rejects a presenter that fails schema (missing required name)", () => {
  assert.throws(
    () => assembleBundle({ bundleId: "bundle-8", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys, presenter: { statement: "no name" } }),
    /presenter fails schema/
  );
});
