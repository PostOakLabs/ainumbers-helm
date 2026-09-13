import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-sigstore-verify-test-"));
process.env.HELM_HOME = TMP;

const { verifySigstoreBundleOffline, sigstoreAttestationBundleSpec, TRUSTED_ROOT_SHA256 } = await import("./sigstore-verify.mjs");
const { loadOrCreateKeys } = await import("./keys.mjs");
const { sealBundleObject } = await import("./bundle.mjs");

const golden = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "sigstore", "golden.sigstore.json"), "utf8"));
const tampered = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "sigstore", "tampered.sigstore.json"), "utf8"));
const messageSignature = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "sigstore", "message-signature.sigstore.json"), "utf8"));

// The subject the golden bundle's signature actually covers: decoded from
// the DSSE payload inside the bundle (never hand-copied), so the sealing
// tests below always state exactly what the signature attests.
const goldenStatement = JSON.parse(Buffer.from(golden.dsseEnvelope.payload, "base64").toString("utf8"));
const MESSAGE_SIGNATURE_ARTIFACT_BYTES = Buffer.from(
  "helm messageSignature fixture: the artifact bytes this bundle signs. Never verify as genuine: self-signed fixture key.\n",
  "utf8"
);
const MESSAGE_SIGNATURE_ARTIFACT_SHA256 = "640d9a54cf56c1a0bb277ea3782a25420fc50a82059340c88a89cb0f0f62098f";

// GREEN control (SO #40(b)): a genuine, published Sigstore bundle (real
// GitHub-Actions-signed SLSA provenance for @sigstore/verify@4.1.2 — see
// fixtures/sigstore/README.md) verifies clean against the pinned trust root.
test("sigstore-verify: GREEN control — genuine bundle verifies offline", () => {
  const result = verifySigstoreBundleOffline(golden);
  assert.equal(result.valid, true);
  assert.equal(result.trustedRootSha256, TRUSTED_ROOT_SHA256);
  assert.equal(
    result.certificateIdentity.subjectAlternativeName,
    "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
  );
  assert.equal(result.certificateIdentity.issuer, "https://token.actions.githubusercontent.com");
  assert.equal(result.tlogEntries.length, 1);
});

// RED control (SO #40(b)): the SAME bundle with one bit flipped in the DSSE
// signature fails with the exact error text a signature-mismatch produces —
// proves the verifier actually checks the signature, not just bundle shape.
test("sigstore-verify: RED control — tampered signature is rejected with exact error text", () => {
  const result = verifySigstoreBundleOffline(tampered);
  assert.equal(result.valid, false);
  assert.equal(result.errorName, "VerificationError");
  assert.equal(result.reason, "tlog entry signature mismatch");
});

test("sigstore-verify: malformed bundle JSON fails closed, does not throw", () => {
  const result = verifySigstoreBundleOffline({ not: "a bundle" });
  assert.equal(result.valid, false);
  assert.match(result.reason, /malformed_bundle/);
});

// NEVER-throws contract, structurally-parseable-but-garbage material: these
// bundles are valid bundle JSON (bundleFromJSON parses them) but their
// verificationMaterial is not valid DER, which makes the vendored
// toSignedEntity() parser throw. The wrapper must convert that into a
// { valid: false } result — an uncaught exception here would crash a
// long-lived caller that was promised a result object.
test("sigstore-verify: cert rawBytes that are not valid DER fail closed as a result, not a throw", () => {
  const garbageCert = JSON.parse(JSON.stringify(golden));
  garbageCert.verificationMaterial.certificate.rawBytes = Buffer.from("this is not a certificate").toString("base64");
  const result = verifySigstoreBundleOffline(garbageCert);
  assert.equal(result.valid, false);
  assert.match(result.reason, /unparseable_verification_material/);
  assert.equal(result.trustedRootSha256, TRUSTED_ROOT_SHA256);
});

test("sigstore-verify: garbage rfc3161 signedTimestamp fails closed as a result, not a throw", () => {
  const garbageTs = JSON.parse(JSON.stringify(golden));
  garbageTs.verificationMaterial.timestampVerificationData = {
    rfc3161Timestamps: [{ signedTimestamp: Buffer.from("garbage").toString("base64") }],
  };
  const result = verifySigstoreBundleOffline(garbageTs);
  assert.equal(result.valid, false);
  assert.match(result.reason, /unparseable_verification_material/);
});

// artifact contract: messageSignature bundles verify raw bytes, never a
// digest-only reference. The fixture bundle is signed by a throwaway
// self-signed key (see fixtures/sigstore/README.md), so the full verify
// path below can never go green — what these tests pin is the parameter
// contract and fail-closed behavior at every stage.
test("sigstore-verify: messageSignature bundle with a digest-only artifact is rejected as artifact_bytes_required", () => {
  const result = verifySigstoreBundleOffline(messageSignature, { artifact: { sha256: MESSAGE_SIGNATURE_ARTIFACT_SHA256 } });
  assert.equal(result.valid, false);
  assert.match(result.reason, /artifact_bytes_required/);
  assert.equal(result.errorName, undefined);
});

test("sigstore-verify: messageSignature bundle with no artifact at all is rejected as artifact_bytes_required", () => {
  const result = verifySigstoreBundleOffline(messageSignature);
  assert.equal(result.valid, false);
  assert.match(result.reason, /artifact_bytes_required/);
});

test("sigstore-verify: messageSignature bundle with a malformed artifact shape is rejected as artifact_malformed", () => {
  const result = verifySigstoreBundleOffline(messageSignature, { artifact: { md5: "nope" } });
  assert.equal(result.valid, false);
  assert.match(result.reason, /artifact_malformed/);
});

test("sigstore-verify: messageSignature fixture's messageDigest matches its documented artifact bytes", () => {
  const digest = createHash("sha256").update(MESSAGE_SIGNATURE_ARTIFACT_BYTES).digest("hex");
  assert.equal(digest, MESSAGE_SIGNATURE_ARTIFACT_SHA256);
  assert.equal(
    Buffer.from(messageSignature.messageSignature.messageDigest.digest, "base64").toString("hex"),
    MESSAGE_SIGNATURE_ARTIFACT_SHA256
  );
});

test("sigstore-verify: messageSignature bundle with raw bytes runs the real verify path and fails closed (fixture key is not Fulcio-signed, no tlog entry)", () => {
  const result = verifySigstoreBundleOffline(messageSignature, { artifact: { bytes: MESSAGE_SIGNATURE_ARTIFACT_BYTES } });
  assert.equal(result.valid, false);
  assert.ok(result.reason && result.reason.length > 0);
  assert.equal(result.trustedRootSha256, TRUSTED_ROOT_SHA256);
});

test("sigstore-verify: a bare Buffer artifact is accepted (equivalent to { bytes })", () => {
  const viaBare = verifySigstoreBundleOffline(messageSignature, { artifact: MESSAGE_SIGNATURE_ARTIFACT_BYTES });
  const viaWrapped = verifySigstoreBundleOffline(messageSignature, { artifact: { bytes: MESSAGE_SIGNATURE_ARTIFACT_BYTES } });
  assert.equal(viaBare.valid, viaWrapped.valid);
  assert.equal(viaBare.reason, viaWrapped.reason);
});

test("sigstore-verify: bundleDigest is over the re-serialized parsed object, not the on-disk file bytes", () => {
  // The fixture file on disk is pretty-printed; hashing its bytes gives a
  // DIFFERENT digest than what the verifier records. Documented semantics:
  // re-read + JSON.parse + JSON.stringify, then hash.
  const fileBytes = createHash("sha256").update(readFileSync(join(HERE, "..", "fixtures", "sigstore", "golden.sigstore.json"))).digest("hex");
  const reparsed = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "sigstore", "golden.sigstore.json"), "utf8"));
  const result = verifySigstoreBundleOffline(reparsed);
  assert.equal(result.bundleDigest, `sha256:${createHash("sha256").update(Buffer.from(JSON.stringify(reparsed))).digest("hex")}`);
  assert.notEqual(result.bundleDigest, `sha256:${fileBytes}`);
});

test("sigstore-verify: TRUSTED_ROOT_SHA256 matches the pinned file's actual bytes (PIN.md's declared digest)", () => {
  assert.equal(TRUSTED_ROOT_SHA256, "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66");
});

// Structural + runtime proof that verification never touches the network —
// this is the row's other required gate ("demonstrated, not asserted").
test("sigstore-verify: zero network calls even with http/https/fetch hard-blocked", () => {
  const originalRequest = http.request;
  const originalGet = http.get;
  const originalHttpsRequest = https.request;
  const originalHttpsGet = https.get;
  const originalFetch = globalThis.fetch;
  const blocked = () => {
    throw new Error("NETWORK CALL ATTEMPTED during offline verify — this must never happen");
  };
  http.request = blocked;
  http.get = blocked;
  https.request = blocked;
  https.get = blocked;
  globalThis.fetch = blocked;
  try {
    const result = verifySigstoreBundleOffline(golden);
    assert.equal(result.valid, true);
  } finally {
    http.request = originalRequest;
    http.get = originalGet;
    https.request = originalHttpsRequest;
    https.get = originalHttpsGet;
    globalThis.fetch = originalFetch;
  }
});

test("sigstore-verify: verifier module source imports no network module (structural check)", () => {
  const src = readFileSync(join(HERE, "sigstore-verify.mjs"), "utf8");
  assert.doesNotMatch(src, /require\((["'])(node:)?(http|https|dns|net)\1\)/);
  assert.doesNotMatch(src, /from\s+["'](node:)?(http|https|dns|net)["']/);
  assert.doesNotMatch(src, /\bfetch\(/);
});

// Digest wiring into the evidence bundle (row fence: "trusted-root digest
// recorded in the evidence bundle"): sigstoreAttestationBundleSpec()'s
// output, once sealed by hub/bundle.mjs's own sealBundleObject(), carries
// TRUSTED_ROOT_SHA256 inside its signed predicate — a verifier of the
// evidence bundle later can read it straight off the envelope, no re-run of
// sigstore verification required.
//
// The subject sealed here is the bundle statement's OWN subject (decoded
// from the DSSE payload above), because subject sealing is subject
// cross-checking: an earlier version of this test sealed a fabricated
// sha256 digest the bundle never attested, which is exactly the
// attestation-swap this cross-check exists to make impossible.
test("sigstore-verify: trusted-root digest is wired into a sealed evidence-bundle object", () => {
  const keys = loadOrCreateKeys();
  const spec = sigstoreAttestationBundleSpec({
    subject: goldenStatement.subject,
    bundleJson: golden,
  });
  assert.equal(spec.kind, "connector_attestation");
  assert.equal(spec.predicate.trusted_root_sha256, TRUSTED_ROOT_SHA256);
  assert.equal(spec.predicate.verified_offline, true);
  // The predicate records the subjects the signature actually covers, next
  // to the caller's claim, so the cross-check is visible to evidence
  // consumers rather than taken on faith.
  assert.deepEqual(spec.predicate.statement_subjects, goldenStatement.subject);

  const sealed = sealBundleObject(spec, keys);
  assert.equal(sealed.trust_label, "connector_asserted");
  const payload = JSON.parse(Buffer.from(sealed.envelope.payload, "base64").toString("utf8"));
  assert.equal(payload.predicate.trusted_root_sha256, TRUSTED_ROOT_SHA256);
  assert.deepEqual(payload.predicate.statement_subjects, goldenStatement.subject);
});

// SUBJECT CROSS-CHECK, red: a subject whose digest the verified bundle
// never attested must be refused. A genuine attestation for artifact Y must
// not be able to back a sealed claim about artifact X: the fabricated
// sha256 below does not appear in the golden statement's (sha512-only)
// subject digests.
test("sigstore-verify: refuses to seal a subject digest the verified statement does not cover", () => {
  assert.throws(
    () =>
      sigstoreAttestationBundleSpec({
        subject: [{ name: "@sigstore/verify@4.1.2", digest: { sha256: "0".repeat(64) } }],
        bundleJson: golden,
      }),
    /not covered by the bundle's signature.*sha256:0{64}/
  );
});

// Partial overclaim: a REAL covered digest padded with one fabricated one
// must also be refused — the sealed claim may not exceed what was signed.
test("sigstore-verify: refuses to seal a subject that mixes a covered digest with a fabricated one", () => {
  const realSha512 = goldenStatement.subject[0].digest.sha512;
  assert.throws(
    () =>
      sigstoreAttestationBundleSpec({
        subject: [
          {
            name: "@sigstore/verify@4.1.2",
            digest: { sha512: realSha512.toUpperCase(), sha256: "f".repeat(64) },
          },
        ],
        bundleJson: golden,
      }),
    /not covered by the bundle's signature.*sha256:f{64}/
  );
});

// A subject with no digests at all cannot be checked against anything.
test("sigstore-verify: refuses to seal a digest-less subject", () => {
  assert.throws(
    () => sigstoreAttestationBundleSpec({ subject: [{ name: "@sigstore/verify@4.1.2" }], bundleJson: golden }),
    /carries no digests/
  );
});

// Case-insensitivity is normalization, not a loophole: uppercase hex of the
// real digest still cross-checks clean.
test("sigstore-verify: subject digest comparison normalizes hex case", () => {
  const spec = sigstoreAttestationBundleSpec({
    subject: [{ name: "@sigstore/verify@4.1.2", digest: { sha512: goldenStatement.subject[0].digest.sha512.toUpperCase() } }],
    bundleJson: golden,
  });
  assert.equal(spec.predicate.verified_offline, true);
});

test("sigstore-verify: refuses to seal a false attestation from a tampered bundle", () => {
  assert.throws(
    () =>
      sigstoreAttestationBundleSpec({
        subject: [{ name: "tampered", digest: { sha256: "0".repeat(64) } }],
        bundleJson: tampered,
      }),
    /does not verify offline/
  );
});
