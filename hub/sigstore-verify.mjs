// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Offline Sigstore bundle verification (HELM-SIGSTORE-OFFLINE-VERIFY-1,
// staged off research/LEGALOPS-UNBUILT-TRIAGE-2026-08-20.md — "strongest of
// the parked signing items; unlocks verifying npm/GitHub attestations inside
// Helm bundles"). Verifies a Sigstore bundle (the format both `gh attestation`
// and `npm publish --provenance` produce) entirely against the pinned trust
// root vendored alongside this file — NO NETWORK CALL AT VERIFY TIME, not
// even to refresh the trust root. See hub/vendored/sigstore/trusted-root/PIN.md
// for how that root was pinned and how to re-pin it.
//
// SIGSTORE-STALE-ROOT-CAVEAT: because the trust root is a static pin, a
// signing certificate issued after this root's Fulcio validity window closes
// will fail to verify here even though it is genuinely valid against the
// live Sigstore instance. That is the correct, safe failure mode for an
// offline verifier (it never silently trusts something it can't check) — the
// fix is re-pinning (PIN.md), not relaxing the check.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR_ROOT = join(HERE, "vendored", "sigstore");
const TRUSTED_ROOT_PATH = join(VENDOR_ROOT, "trusted-root", "trusted_root.json");

// Resolution relies on the vendored node_modules/@sigstore/* layout (see
// hub/vendored/sigstore/MANIFEST.json) — these are bare-specifier requires,
// same as the packages ship upstream, resolved via Node's normal
// node_modules walk-up because we hand-placed them in that exact shape
// (STANDING ORDERS #10: zero npm install, zero rewritten import paths).
const requireVendored = createRequire(join(VENDOR_ROOT, "MANIFEST.json"));
const { TrustedRoot } = requireVendored("@sigstore/protobuf-specs");
const { bundleFromJSON } = requireVendored("@sigstore/bundle");
const { toTrustMaterial } = requireVendored("@sigstore/verify/dist/trust/index.js");
const { toSignedEntity } = requireVendored("@sigstore/verify/dist/bundle/index.js");
const { Verifier } = requireVendored("@sigstore/verify/dist/verifier.js");

const trustedRootBytes = readFileSync(TRUSTED_ROOT_PATH);
export const TRUSTED_ROOT_SHA256 = createHash("sha256").update(trustedRootBytes).digest("hex");

const trustedRoot = TrustedRoot.fromJSON(JSON.parse(trustedRootBytes.toString("utf8")));
const trustMaterial = toTrustMaterial(trustedRoot);

// Verifier instance is stateless across calls (trustMaterial is fixed) and
// safe to reuse — building it touches no network, just parses the pinned
// trust root once.
function makeVerifier(opts) {
  return new Verifier(trustMaterial, {
    ctlogThreshold: opts.ctlogThreshold ?? 1,
    tlogThreshold: opts.tlogThreshold ?? 1,
  });
}

function digestHex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Verifies one Sigstore bundle (the JSON object as produced by `gh
// attestation verify --format json`'s bundle field, `npm audit signatures`'
// underlying attestation bundle, or any `.sigstore.json` file) fully
// offline. bundleJson: parsed Sigstore bundle object. artifact: optional
// { sha256: hex } — required only for a messageSignature bundle (a DSSE/
// in-toto attestation bundle carries its own subject digests and does not
// need one). Returns a plain result object, NEVER throws on a bad/tampered
// bundle — that's the caller's TAMPERED-BUNDLE control to assert against.
export function verifySigstoreBundleOffline(bundleJson, { artifact, ctlogThreshold, tlogThreshold } = {}) {
  const bundleDigest = `sha256:${digestHex(Buffer.from(JSON.stringify(bundleJson)))}`;
  let bundle;
  try {
    bundle = bundleFromJSON(bundleJson);
  } catch (e) {
    return { valid: false, reason: `malformed_bundle: ${e.message}`, trustedRootSha256: TRUSTED_ROOT_SHA256, bundleDigest };
  }

  const entity = toSignedEntity(bundle, artifact);
  const verifier = makeVerifier({ ctlogThreshold, tlogThreshold });

  let signer;
  try {
    signer = verifier.verify(entity);
  } catch (e) {
    return {
      valid: false,
      reason: e.message,
      errorName: e.name,
      trustedRootSha256: TRUSTED_ROOT_SHA256,
      bundleDigest,
    };
  }

  const tlogEntries = (bundle.verificationMaterial.tlogEntries ?? []).map((t) => ({
    logIndex: t.logIndex ?? null,
    integratedTime: t.integratedTime ?? null,
  }));

  return {
    valid: true,
    trustedRootSha256: TRUSTED_ROOT_SHA256,
    bundleDigest,
    certificateIdentity: signer.identity
      ? {
          subjectAlternativeName: signer.identity.subjectAlternativeName ?? null,
          issuer: signer.identity.extensions?.issuer ?? null,
        }
      : null,
    tlogEntries,
  };
}

// Builds the { kind, subject, predicate, trustLabel } spec that
// hub/bundle.mjs's sealBundleObject()/assembleBundle() expects, from a
// Sigstore verification result — this is the "digest wiring into the
// evidence bundle" the row's fence requires: trustedRootSha256 travels
// inside the sealed, signed predicate, so anyone verifying the evidence
// bundle later (hub/bundle.mjs's verifyBundle(), fully offline) can see
// exactly which pinned trust root the sigstore check ran against, without
// re-running the sigstore verification itself. Throws if verification did
// not succeed — callers must call verifySigstoreBundleOffline() first and
// decide what to do with a failed result themselves (this function refuses
// to seal a false "verified" claim into evidence).
export function sigstoreAttestationBundleSpec({ subject, bundleJson, artifact }) {
  const result = verifySigstoreBundleOffline(bundleJson, { artifact });
  if (!result.valid) {
    throw new Error(`sigstoreAttestationBundleSpec: bundle does not verify offline (${result.reason}) — refusing to seal a false attestation into the evidence bundle`);
  }
  return {
    kind: "connector_attestation",
    subject,
    predicate: {
      source: "sigstore_bundle",
      verified_offline: true,
      trusted_root_sha256: result.trustedRootSha256,
      sigstore_bundle_digest: result.bundleDigest,
      certificate_identity: result.certificateIdentity,
      tlog_entries: result.tlogEntries,
    },
  };
}
