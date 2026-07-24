// Evidence bundle assembler (HELM-H7, SPEC.md §26.7): packages a run's §26.4
// objects + checkpoints + anchors into a self-contained, offline-verifiable
// archive. Every entry is signed (§26.2 DSSE/in-toto), labeled with EXACTLY
// one §26.6 trust label (never collapsed), and the archive is redacted by
// default before export.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { buildStatement, emitEnvelope, verifyEnvelope, helmPredicateType } from "./envelope.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { verifyBundle as verifyBundleOffline, verifyAnchorBinding } from "../ui/lib/verify-bundle.mjs";
import { envelopeDigest as envelopeDigestOffline } from "../ui/lib/verify-envelope.mjs";
import { buildStandaloneVerifierHtml } from "../ui/lib/standalone-verifier.mjs";
import { buildAuditorHtml } from "../ui/lib/auditor-pdf.mjs";
import { buildZip } from "../ui/lib/zip-writer.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "schema", "evidence_bundle_manifest.schema.json"), "utf8")
);
const PRESENTER_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "schema", "presenter.schema.json"), "utf8")
);

export const REDACTION_PROFILE = "default-v1";

// §26.4 object kind -> §26.6 trust label. A kernel-run step result (this
// module's own "step_result" kind, produced by kernel-runner.mjs) is
// kernel_verified by construction — the runner already proved reproduction
// before returning. Callers MAY override per-object when a kind legitimately
// needs a different label than its default (never to weaken §26.6's meaning,
// only e.g. a hash-only passthrough that never touched a kernel or a human).
const DEFAULT_TRUST_LABEL = {
  step_result: "kernel_verified",
  execution_state: "kernel_verified",
  connector_attestation: "connector_asserted",
  policy_decision: "hash_verified",
  review_task: "human_attested",
  review_decision: "human_attested",
  override: "human_attested",
  agent_delegation: "hash_verified",
  external_action_intent: "hash_verified",
  external_action_receipt: "external_ack_captured",
  disclosure_receipt: "hash_verified",
};

// Structural redaction backstop (§26.7 "no secret values, no raw credential
// material, no unredacted payloads"): objects entering a bundle are expected
// to already be digest-only summaries (e.g. connector_attestation carries
// payload_digest, never raw bytes) — this refuses known-dangerous field
// names outright so a mistake upstream can't leak through silently.
const FORBIDDEN_FIELD_NAMES = new Set([
  "access_token", "refresh_token", "id_token", "secret", "secretKey", "privateKey",
  "password", "api_key", "raw_payload", "payload_bytes", "payload_body",
]);

function assertRedacted(obj, path = "$") {
  if (Array.isArray(obj)) { obj.forEach((v, i) => assertRedacted(v, `${path}[${i}]`)); return; }
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (FORBIDDEN_FIELD_NAMES.has(k)) {
        throw new Error(`evidence bundle: default redaction violated — "${path}.${k}" looks like a secret/raw payload and must not be exported`);
      }
      assertRedacted(v, `${path}.${k}`);
    }
  }
}

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

function sha256ref(hex) {
  return `sha256:${hex}`;
}

// digest of a signed envelope = digest of its statement (the same convention
// checkpoint.mjs uses for journal_root_digest) — a verifier can recompute it
// from the envelope alone, with zero network access.
function statementOf(envelope) {
  return JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
}

function envelopeDigest(envelope) {
  return sha256ref(jcsDigestHex(statementOf(envelope)));
}

// Signs one §26.4 object into a DSSE envelope. spec: { kind, subject,
// predicate, trustLabel? }. subject follows §26.2 (digests of bound
// artifacts, e.g. [{ name, digest: { sha256 } }]).
export function sealBundleObject({ kind, subject, predicate, trustLabel }, keys) {
  assertRedacted(predicate);
  const label = trustLabel ?? DEFAULT_TRUST_LABEL[kind];
  if (!label) throw new Error(`evidence bundle: no default trust label for kind "${kind}" — pass trustLabel explicitly`);
  const statement = buildStatement({ subject, predicateType: helmPredicateType(kind), predicate });
  const envelope = emitEnvelope(statement, keys);
  return { kind, digest: envelopeDigest(envelope), trust_label: label, envelope };
}

// specs: array of { kind, subject, predicate, trustLabel? } (raw objects to
// seal) OR already-sealed { kind, digest, trust_label, envelope } (e.g. a
// checkpoint envelope reused as-is). checkpoints: array of checkpoint.mjs
// buildCheckpoint() results ({ checkpointSeq, journalRootDigest, envelope }).
export function assembleBundle({ bundleId, runId, workflowManifestDigest, specs, checkpoints = [], anchorsRef = [], keys, presenter }) {
  const sealed = specs.map((s) => (s.envelope && s.digest ? s : sealBundleObject(s, keys)));
  const entries = sealed.map(({ kind, digest, trust_label }) => ({ kind, digest, trust_label }));
  const checkpointsRef = checkpoints.map((cp) => envelopeDigest(cp.envelope));

  const manifestPredicate = {
    bundle_id: bundleId,
    run_id: runId,
    workflow_manifest_digest: workflowManifestDigest,
    entries,
    checkpoints_ref: checkpointsRef,
    anchors_ref: anchorsRef,
    redaction_profile: REDACTION_PROFILE,
  };
  const errs = validate(MANIFEST_SCHEMA, manifestPredicate);
  if (errs.length) throw new Error(`evidence bundle: manifest fails schema — ${errs.join("; ")}`);

  const manifestStatement = buildStatement({
    subject: [{ name: "workflow_manifest", digest: { sha256: workflowManifestDigest.replace(/^sha256:/, "") } }],
    predicateType: helmPredicateType("evidence_bundle_manifest"),
    predicate: manifestPredicate,
  });
  const manifestEnvelope = emitEnvelope(manifestStatement, keys);

  // presenter (HELM-P4-J2): deliberately NOT part of manifestPredicate — it
  // travels as an unsigned sibling field so co-brand swaps can never move
  // bundle.manifest.envelope's signed digest or affect verifyBundle().
  if (presenter !== undefined) {
    const presenterErrs = validate(PRESENTER_SCHEMA, presenter);
    if (presenterErrs.length) throw new Error(`evidence bundle: presenter fails schema — ${presenterErrs.join("; ")}`);
  }

  return {
    manifest: { predicate: manifestPredicate, envelope: manifestEnvelope },
    objects: sealed,
    checkpoints,
    ...(presenter !== undefined ? { presenter } : {}),
  };
}

// Zero-network, offline verification (§26.7 conformance requirement).
// Checks: manifest envelope + schema, every entry's object envelope verifies
// and its recomputed digest/kind/trust_label match the manifest exactly (no
// silent substitution), every checkpoint envelope verifies and is referenced,
// and the whole bundle passes the redaction backstop. Returns
// { valid, reasons[] } — never throws on a bad bundle (that's what a
// TAMPERED-BUNDLE fixture asserts against).
export function verifyBundle(bundle, publicKeys) {
  const reasons = [];

  const manifestResult = verifyEnvelope(bundle.manifest.envelope, publicKeys);
  if (!manifestResult.valid) {
    reasons.push("manifest_envelope_invalid");
    return { valid: false, reasons };
  }
  const predicate = manifestResult.statement.predicate;
  const schemaErrs = validate(MANIFEST_SCHEMA, predicate);
  if (schemaErrs.length) reasons.push(`manifest_schema_invalid: ${schemaErrs.join("; ")}`);
  if (jcsDigestHex(predicate) !== jcsDigestHex(bundle.manifest.predicate)) {
    reasons.push("manifest_predicate_mismatch");
  }

  const objectsByDigest = new Map(bundle.objects.map((o) => [o.digest, o]));
  for (const entry of predicate.entries) {
    const obj = objectsByDigest.get(entry.digest);
    if (!obj) { reasons.push(`entry_object_missing:${entry.digest}`); continue; }
    if (obj.kind !== entry.kind) { reasons.push(`entry_kind_mismatch:${entry.digest}`); continue; }
    if (obj.trust_label !== entry.trust_label) { reasons.push(`entry_trust_label_mismatch:${entry.digest}`); continue; }
    const objResult = verifyEnvelope(obj.envelope, publicKeys);
    if (!objResult.valid) { reasons.push(`entry_envelope_invalid:${entry.digest}`); continue; }
    if (envelopeDigest(obj.envelope) !== entry.digest) { reasons.push(`entry_digest_mismatch:${entry.digest}`); continue; }
    try {
      assertRedacted(objResult.statement.predicate);
    } catch {
      reasons.push(`entry_redaction_violated:${entry.digest}`);
    }
  }

  const checkpointDigests = new Set((bundle.checkpoints ?? []).map((cp) => envelopeDigest(cp.envelope)));
  for (const ref of predicate.checkpoints_ref) {
    if (!checkpointDigests.has(ref)) { reasons.push(`checkpoint_missing:${ref}`); continue; }
  }
  for (const cp of bundle.checkpoints ?? []) {
    const cpResult = verifyEnvelope(cp.envelope, publicKeys);
    if (!cpResult.valid) reasons.push(`checkpoint_envelope_invalid:${envelopeDigest(cp.envelope)}`);
  }

  return { valid: reasons.length === 0, reasons };
}

// Node KeyObject/Uint8Array keypair (loadOrCreateKeys() shape) -> the base64
// SPKI shape the WebCrypto-based offline verifier chain (ui/lib/verify-*.mjs,
// embedded in verify.html) expects — same conversion gen-verify-demo-fixture.mjs
// hand-does for the Verify view's built-in demo.
export function browserPublicKeys(keys) {
  return {
    ed25519SpkiB64: keys.ed25519.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    mldsa44B64: Buffer.from(keys.mldsa44.publicKey).toString("base64"),
  };
}

// HELM-P3-V9 (HELM-PHASE3-BUILD-SPEC.md §3 items 1+3): packages an assembled
// bundle into bundle.zip — the shareable, offline-verifiable artifact. Runs
// the SAME WebCrypto verify chain the embedded verify.html will run (Node
// 22.5+ ships globalThis.crypto.subtle, so this is the real code path, not a
// simulation) both to prove the bundle actually verifies before it ships and
// to source the auditor.html's per-object/per-checkpoint detail. keys: the
// Node keypair (loadOrCreateKeys() shape) that signed the bundle.
export async function exportBundleZip(bundle, keys, { generatedAt } = {}) {
  const publicKeys = browserPublicKeys(keys);
  const verifyResult = await verifyBundleOffline(bundle, publicKeys);
  const manifestDigest = await envelopeDigestOffline(bundle.manifest.envelope);

  const checkpointsWithBinding = verifyResult.detail.checkpoints.map((cp) => {
    if (!cp.predicate) return cp;
    const anchors = (cp.predicate.anchors ?? []).map((a) => ({
      ...a,
      binding: verifyAnchorBinding(a, cp.predicate.journal_root_digest),
    }));
    return { ...cp, predicate: { ...cp.predicate, anchors } };
  });

  const verifyHtml = buildStandaloneVerifierHtml({ bundle, publicKeys });
  const auditorHtml = buildAuditorHtml({
    bundle,
    entries: verifyResult.detail.entries,
    checkpoints: checkpointsWithBinding,
    manifestDigest,
    generatedAt,
  });
  const readme = `Helm evidence bundle — ${bundle.manifest.predicate.bundle_id}\n\n` +
    `bundle.json   — the raw signed evidence bundle (this IS the evidence; everything else here is a view onto it)\n` +
    `verify.html   — open this in any browser, fully offline, to re-verify the bundle from scratch\n` +
    `auditor.html  — human-readable audit record; print or "print to PDF" for paper records\n\n` +
    `Bundle verified ${verifyResult.valid ? "VALID" : "INVALID"} at export time` +
    (verifyResult.reasons.length ? `: ${verifyResult.reasons.join("; ")}\n` : ".\n");

  return {
    valid: verifyResult.valid,
    reasons: verifyResult.reasons,
    zip: buildZip([
      { name: "bundle.json", data: JSON.stringify(bundle, null, 2) },
      { name: "verify.html", data: verifyHtml },
      { name: "auditor.html", data: auditorHtml },
      { name: "README.txt", data: readme },
    ]),
  };
}
