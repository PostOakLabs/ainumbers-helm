// Browser-side, zero-network evidence bundle verifier (HELM-U3; SPEC.md §26.7,
// §26.8). Mirrors hub/bundle.mjs verifyBundle() + hub/checkpoint.mjs's
// self-consistency check, minus the "live daemon journal" comparison
// verifyCheckpoint() does — this view has no daemon (D1/the row: "works with a
// bundle file and no daemon"), so a checkpoint is only checked against ITSELF
// (journal_root_digest recomputes from its own streams[]), not against live
// journal state. That's a real scope boundary, not an oversight — it's called
// out explicitly in the Verify view's "what was NOT checked" copy fence.
import { verifyEnvelope, jcsDigestHex, envelopeDigest, statementOf } from "./verify-envelope.mjs";
import { parseRfc3161MessageImprint } from "../vendored/der.mjs";
import { validate } from "../vendored/schema-validator.mjs";
import EVIDENCE_BUNDLE_MANIFEST_SCHEMA from "../vendored/schemas/evidence_bundle_manifest.schema.mjs";

const FORBIDDEN_FIELD_NAMES = new Set([
  "access_token", "refresh_token", "id_token", "secret", "secretKey", "privateKey",
  "password", "api_key", "raw_payload", "payload_bytes", "payload_body",
]);

function assertRedacted(obj, path = "$") {
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => assertRedacted(v, `${path}[${i}]`));
    return;
  }
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (FORBIDDEN_FIELD_NAMES.has(k)) {
        throw new Error(`"${path}.${k}" looks like a secret/raw payload and must not be exported`);
      }
      assertRedacted(v, `${path}.${k}`);
    }
  }
}

// Checkpoint self-consistency only (no live daemon to compare stream heads
// against — see module header). anchors[] structural check is separate
// (verifyAnchor below) since it can partially succeed per-anchor.
export async function verifyCheckpointOffline(checkpoint, publicKeys) {
  const result = await verifyEnvelope(checkpoint.envelope, publicKeys);
  if (!result.valid) return { valid: false, reason: "envelope" };
  const { predicate } = result.statement;
  if (!Array.isArray(predicate.streams) || !predicate.streams.every((s) => s && typeof s.stream_id === "string" && Number.isInteger(s.journal_seq) && typeof s.rh === "string")) {
    return { valid: false, reason: "malformed_streams" };
  }
  // hub/checkpoint.mjs's own journal_root_digest is bare hex, NOT "sha256:"-
  // prefixed (its verifyCheckpoint() compares the same way) — schema/
  // checkpoint.schema.json's sha256ref pattern disagrees with that, a
  // pre-existing S1/H3 drift outside this WU's U-class scope (flagged, not
  // silently fixed here). Recompute the SAME way the daemon does so a real
  // checkpoint isn't falsely rejected by a stricter check than the producer
  // itself applies.
  const expectedDigest = await jcsDigestHex(predicate.streams);
  if (expectedDigest !== predicate.journal_root_digest) {
    return { valid: false, reason: "journal_root_digest_mismatch" };
  }
  return { valid: true, reason: null, predicate };
}

// Structural-only (§26.7 zero-network default): confirms the anchor's proof is
// BOUND to the checkpoint it claims to cover (messageImprint == journal root
// digest for rfc3161; presence + digest match for opentimestamps). Does NOT
// verify the TSA signature chain or the OTS Bitcoin block proof — see
// ../vendored/der.mjs's header and the Verify view's copy fence.
export function verifyAnchorBinding(anchor, expectedHashHex) {
  if (anchor.type === "rfc3161") {
    if (!anchor.der && !anchor.proof) return { checked: false, bound: null, reason: "no proof bytes to bind" };
    try {
      const { hashedMessageHex, genTime, policyOid } = parseRfc3161MessageImprint(anchor.der ?? anchor.proof);
      return { checked: true, bound: hashedMessageHex === expectedHashHex, genTime, policyOid };
    } catch (err) {
      return { checked: true, bound: false, reason: err.message };
    }
  }
  if (anchor.type === "opentimestamps") {
    // Phase 1 stores only the pending calendar attestation (anchor-client.mjs);
    // there is no Merkle-to-block-header proof yet to bind structurally.
    return { checked: false, bound: null, reason: "pending calendar attestation only — not yet upgraded to a Bitcoin block proof (Phase 1 scope)" };
  }
  // R15-F5/P3-D4: a queued/skipped marker is NOT an error — relay-blocked
  // (or fully egress-blocked) is an explicit, expected state, and this
  // neutral branch is what makes §5 exit-gate #1 ("relay-blocked, tool 100%
  // functional") true for the offline verifier specifically. `queued` = a
  // client-side retry is still possible before export; `skipped` = exported
  // with anchoring never attempted (zero-egress copy).
  if (anchor.type === "queued" || anchor.type === "skipped") {
    return { checked: true, bound: null, neutral: true, status: anchor.type, reason: anchor.reason };
  }
  return { checked: false, bound: null, reason: `unrecognized anchor type "${anchor.type}"` };
}

// bundle: { manifest: {predicate, envelope}, objects: [{kind,digest,trust_label,envelope}], checkpoints: [{checkpointSeq,journalRootDigest,envelope}] }
// publicKeys: { ed25519SpkiB64, mldsa44B64 }
// Returns { valid, reasons[], detail } — never throws on a bad bundle (a
// tampered bundle is expected to come back { valid: false, reasons: [...] }).
export async function verifyBundle(bundle, publicKeys) {
  const reasons = [];
  const detail = { manifest: null, entries: [], checkpoints: [] };

  const manifestResult = await verifyEnvelope(bundle.manifest.envelope, publicKeys);
  detail.manifest = { ed25519: manifestResult.ed25519, mldsa44: manifestResult.mldsa44 };
  if (!manifestResult.valid) {
    reasons.push("manifest_envelope_invalid");
    return { valid: false, reasons, detail };
  }
  const predicate = manifestResult.statement.predicate;
  const schemaErrs = validate(EVIDENCE_BUNDLE_MANIFEST_SCHEMA, predicate);
  if (schemaErrs.length) reasons.push(`manifest_schema_invalid: ${schemaErrs.join("; ")}`);
  if ((await jcsDigestHex(predicate)) !== (await jcsDigestHex(bundle.manifest.predicate))) {
    reasons.push("manifest_predicate_mismatch");
  }

  const objectsByDigest = new Map(bundle.objects.map((o) => [o.digest, o]));
  for (const entry of predicate.entries) {
    const obj = objectsByDigest.get(entry.digest);
    const row = { digest: entry.digest, kind: entry.kind, trust_label: entry.trust_label, valid: false };
    if (!obj) {
      reasons.push(`entry_object_missing:${entry.digest}`);
      detail.entries.push(row);
      continue;
    }
    if (obj.kind !== entry.kind) { reasons.push(`entry_kind_mismatch:${entry.digest}`); detail.entries.push(row); continue; }
    if (obj.trust_label !== entry.trust_label) { reasons.push(`entry_trust_label_mismatch:${entry.digest}`); detail.entries.push(row); continue; }
    const objResult = await verifyEnvelope(obj.envelope, publicKeys);
    if (!objResult.valid) { reasons.push(`entry_envelope_invalid:${entry.digest}`); detail.entries.push(row); continue; }
    if ((await envelopeDigest(obj.envelope)) !== entry.digest) { reasons.push(`entry_digest_mismatch:${entry.digest}`); detail.entries.push(row); continue; }
    try {
      assertRedacted(objResult.statement.predicate);
    } catch {
      reasons.push(`entry_redaction_violated:${entry.digest}`);
      detail.entries.push(row);
      continue;
    }
    row.valid = true;
    row.predicate = objResult.statement.predicate;
    detail.entries.push(row);
  }

  const checkpointDigests = new Set();
  for (const cp of bundle.checkpoints ?? []) {
    const digest = await envelopeDigest(cp.envelope);
    checkpointDigests.add(digest);
    const cpResult = await verifyCheckpointOffline(cp, publicKeys);
    detail.checkpoints.push({ digest, checkpointSeq: cp.checkpointSeq, ...cpResult });
    if (!cpResult.valid) reasons.push(`checkpoint_envelope_invalid:${digest}`);
  }
  for (const ref of predicate.checkpoints_ref ?? []) {
    if (!checkpointDigests.has(ref)) reasons.push(`checkpoint_missing:${ref}`);
  }

  return { valid: reasons.length === 0, reasons, detail };
}

export { assertRedacted, statementOf };
