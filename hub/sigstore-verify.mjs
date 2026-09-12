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
//
// `sigstore_bundle_digest` SEMANTICS (read before cross-checking): every
// result below (and every evidence-bundle predicate sealed from one) records
// `bundleDigest` = `sha256:<hex>` where the hash input is the UTF-8 bytes of
// JSON.stringify(<the parsed bundle object>) — a compact re-serialization of
// the JSON you passed in, with whatever key order that object happens to
// carry. It is deterministic for the same parsed object, but it is NOT the
// sha256 of any on-disk file: `sha256sum foo.sigstore.json` will NOT match
// whenever the file is pretty-printed (different bytes). To cross-check a
// sealed digest, re-read the bundle file, JSON.parse it, and hash
// JSON.stringify(parsed) — or hash the exact bytes you would have passed
// here. The digest intentionally pins the LOGICAL bundle (what gets
// verified), not one particular pretty-printing of it.
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
// offline. bundleJson: parsed Sigstore bundle object.
//
// artifact: optional, and its shape depends on the bundle's content type:
//   - DSSE/in-toto attestation bundle (the `gh attestation` / `npm
//     publish --provenance` case): carries its own subject digests inside
//     the signature-covered envelope, so `artifact` may be omitted, given
//     as a digest reference { sha256: hex }, or given as raw bytes
//     { bytes: Buffer } — it is not needed to verify a DSSE bundle.
//   - messageSignature bundle (a detached signature over raw artifact
//     bytes, e.g. `cosign sign-blob` output): the signature is computed
//     over the bytes themselves, so artifact MUST be { bytes: Buffer }
//     (a bare Buffer/Uint8Array is also accepted). A digest-only
//     { sha256: hex } reference cannot verify a messageSignature bundle
//     and fails closed with reason "artifact_bytes_required" — a hash of
//     the artifact is not something a signature over the artifact can be
//     checked against.
//
// Returns a plain result object, NEVER throws on a bad/tampered bundle —
// that's the caller's TAMPERED-BUNDLE control to assert against. This
// includes bundles whose verificationMaterial is structurally parseable
// JSON but cryptographically garbage (e.g. cert rawBytes that are not
// DER, or a truncated RFC 3161 timestamp): those come back as
// { valid: false, reason, errorName } too, never as an exception.
//
// bundleDigest semantics (part of the result contract, see HELM-6 note
// at the top of this file): the digest is computed over the compact
// re-serialization of the parsed bundle object (JSON.stringify of the
// object you passed in), NOT over the bytes of any on-disk file.
export function verifySigstoreBundleOffline(bundleJson, { artifact, ctlogThreshold, tlogThreshold } = {}) {
  const bundleDigest = `sha256:${digestHex(Buffer.from(JSON.stringify(bundleJson)))}`;
  let bundle;
  try {
    bundle = bundleFromJSON(bundleJson);
  } catch (e) {
    return { valid: false, reason: `malformed_bundle: ${e.message}`, trustedRootSha256: TRUSTED_ROOT_SHA256, bundleDigest };
  }

  // Normalize the artifact parameter to raw bytes (or a recorded digest
  // for the DSSE case). Fail closed on shapes we can't act on rather than
  // guessing, and fail closed on a messageSignature bundle whose artifact
  // arrived digest-only: verifying it without the bytes is impossible, and
  // pretending otherwise would turn the digest into a fake identity check.
  let artifactBytes;
  if (Buffer.isBuffer(artifact)) {
    artifactBytes = artifact;
  } else if (artifact instanceof Uint8Array) {
    artifactBytes = Buffer.from(artifact);
  } else if (artifact !== undefined && artifact !== null && typeof artifact === "object") {
    if (Buffer.isBuffer(artifact.bytes) || artifact.bytes instanceof Uint8Array) {
      artifactBytes = Buffer.from(artifact.bytes);
    } else if (typeof artifact.sha256 === "string" && /^[0-9a-fA-F]{64}$/.test(artifact.sha256)) {
      // Digest-only reference: valid for DSSE bundles (which don't need the
      // bytes), rejected below for messageSignature bundles.
    } else {
      return {
        valid: false,
        reason: `artifact_malformed: expected { bytes: Buffer }, { sha256: 64-hex }, or a bare Buffer — got ${JSON.stringify(Object.keys(artifact))}`,
        trustedRootSha256: TRUSTED_ROOT_SHA256,
        bundleDigest,
      };
    }
  } else if (artifact !== undefined && artifact !== null) {
    return {
      valid: false,
      reason: `artifact_malformed: expected { bytes: Buffer }, { sha256: 64-hex }, or a bare Buffer — got ${typeof artifact}`,
      trustedRootSha256: TRUSTED_ROOT_SHA256,
      bundleDigest,
    };
  }
  if (bundle.content?.$case === "messageSignature" && artifactBytes === undefined) {
    return {
      valid: false,
      reason: 'artifact_bytes_required: a messageSignature bundle signs raw artifact bytes; artifact must be { bytes: Buffer } (a { sha256 } digest cannot verify a detached message signature)',
      trustedRootSha256: TRUSTED_ROOT_SHA256,
      bundleDigest,
    };
  }

  // toSignedEntity parses the bundle's cryptographic material (X.509 cert
  // DER, RFC 3161 timestamp DER). Garbage in any of those escapes as an
  // exception from the vendored parser, and this function's contract is
  // that a bad bundle is a RESULT, never a throw — so it gets the same
  // try/catch treatment as bundleFromJSON above.
  let entity;
  try {
    entity = toSignedEntity(bundle, artifactBytes);
  } catch (e) {
    return {
      valid: false,
      reason: `unparseable_verification_material: ${e.message}`,
      errorName: e.name,
      trustedRootSha256: TRUSTED_ROOT_SHA256,
      bundleDigest,
    };
  }
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
//
// SUBJECT CROSS-CHECK (fail closed): a successful verification proves the
// DSSE envelope's signature is genuine — and the envelope's in-toto
// statement, which is inside the signature, lists the subject digests the
// signer actually attested. Nothing in the crypto forces the CALLER's
// `subject` claim to be the same thing, and this function is the one place
// where the two meet, so before sealing it requires every digest on every
// caller-supplied subject entry to appear among the signature-covered
// statement's subject digests (same algorithm, same value, hex compared
// case-insensitively). A subject whose digests don't match — including a
// partially-correct subject that adds one digest the statement never made —
// is refused. For a messageSignature bundle (no in-toto statement) the
// signature covers the artifact bytes themselves, so the caller's subject
// digests must match the sha256 of those verified bytes. The sealed
// predicate records the subjects the signature actually covers
// (statement_subjects) next to the caller's claim, so an evidence consumer
// never has to take the cross-check on faith.
export function sigstoreAttestationBundleSpec({ subject, bundleJson, artifact }) {
  const result = verifySigstoreBundleOffline(bundleJson, { artifact });
  if (!result.valid) {
    throw new Error(`sigstoreAttestationBundleSpec: bundle does not verify offline (${result.reason}) — refusing to seal a false attestation into the evidence bundle`);
  }

  // Collect the "alg:lowercase-hex" digest set the bundle's signature
  // actually covers. A DSSE statement subject looks like
  // { name: "pkg:npm/...", digest: { sha512: "..." } }; a messageSignature
  // bundle covers exactly the sha256 of the verified artifact bytes.
  const covered = new Map(); // "alg:value" -> subject name
  const coveredSubjects = [];
  if (bundleJson.dsseEnvelope) {
    let statement;
    try {
      statement = JSON.parse(Buffer.from(bundleJson.dsseEnvelope.payload, "base64").toString("utf8"));
    } catch (e) {
      throw new Error(`sigstoreAttestationBundleSpec: cannot read the DSSE statement inside the verified bundle (${e.message}) — refusing to seal without knowing what the signature covers`);
    }
    for (const s of statement.subject ?? []) {
      coveredSubjects.push(s);
      for (const [alg, value] of Object.entries(s.digest ?? {})) {
        covered.set(`${alg}:${String(value).toLowerCase()}`, s.name);
      }
    }
  } else if (bundleJson.messageSignature) {
    const bytes = artifact?.bytes ?? artifact;
    if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
      // Unreachable via the public path (verification above already required
      // the bytes) — kept as a fail-closed guard for direct callers.
      throw new Error("sigstoreAttestationBundleSpec: messageSignature bundle verified without raw artifact bytes — refusing to seal");
    }
    const name = subject?.[0]?.name ?? null;
    const s = { name, digest: { sha256: digestHex(bytes) } };
    coveredSubjects.push(s);
    covered.set(`sha256:${s.digest.sha256}`, name);
  } else {
    throw new Error("sigstoreAttestationBundleSpec: bundle carries neither a DSSE envelope nor a message signature — refusing to seal an unknown content type");
  }

  // Every digest the caller claims must be one the signature covers.
  const subjectEntries = Array.isArray(subject) ? subject : [subject];
  if (subjectEntries.length === 0) {
    throw new Error("sigstoreAttestationBundleSpec: empty subject — refusing to seal an attestation with no subject");
  }
  for (const entry of subjectEntries) {
    const digests = Object.entries(entry?.digest ?? {});
    if (digests.length === 0) {
      throw new Error(`sigstoreAttestationBundleSpec: subject ${JSON.stringify(entry?.name ?? entry)} carries no digests — refusing to seal a subject that cannot be checked against the signature-covered statement`);
    }
    for (const [alg, value] of digests) {
      if (typeof value !== "string" || !covered.has(`${alg}:${value.toLowerCase()}`)) {
        throw new Error(
          `sigstoreAttestationBundleSpec: caller-supplied subject is not covered by the bundle's signature: digest ${alg}:${value} is not among the verified statement's subject digests (${[...covered.keys()].join(", ") || "none"}) — refusing to seal a subject the signature does not attest`
        );
      }
    }
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
      statement_subjects: coveredSubjects,
    },
  };
}
