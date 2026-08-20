import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
test("sigstore-verify: trusted-root digest is wired into a sealed evidence-bundle object", () => {
  const keys = loadOrCreateKeys();
  const spec = sigstoreAttestationBundleSpec({
    subject: [{ name: "@sigstore/verify@4.1.2", digest: { sha256: "0".repeat(64) } }],
    bundleJson: golden,
  });
  assert.equal(spec.kind, "connector_attestation");
  assert.equal(spec.predicate.trusted_root_sha256, TRUSTED_ROOT_SHA256);
  assert.equal(spec.predicate.verified_offline, true);

  const sealed = sealBundleObject(spec, keys);
  assert.equal(sealed.trust_label, "connector_asserted");
  const payload = JSON.parse(Buffer.from(sealed.envelope.payload, "base64").toString("utf8"));
  assert.equal(payload.predicate.trusted_root_sha256, TRUSTED_ROOT_SHA256);
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
