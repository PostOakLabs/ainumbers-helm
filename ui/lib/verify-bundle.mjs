// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Browser-side, zero-network evidence bundle verifier (HELM-U3; SPEC.md §26.7,
// §26.8). Mirrors hub/bundle.mjs verifyBundle() + hub/checkpoint.mjs's
// self-consistency check, minus the "live daemon journal" comparison
// verifyCheckpoint() does — this view has no daemon (D1/the row: "works with a
// bundle file and no daemon"), so a checkpoint is only checked against ITSELF
// (journal_root_digest recomputes from its own streams[]), not against live
// journal state. That's a real scope boundary, not an oversight — it's called
// out explicitly in the Verify view's "what was NOT checked" copy fence.
import { verifyEnvelope, jcsDigestHex, envelopeDigest, statementOf } from "./verify-envelope.mjs";
import { parseRfc3161MessageImprint, base64ToBytes } from "../vendored/der.mjs";
import { verifyRfc3161Full } from "./rfc3161-verify.mjs";
import { validate } from "../vendored/schema-validator.mjs";
import EVIDENCE_BUNDLE_MANIFEST_SCHEMA from "../vendored/schemas/evidence_bundle_manifest.schema.mjs";
import { verifyEvidenceEnvelopeReceipt } from "../vendored/evidence-envelope-verify.mjs";

// HELM-ENVELOPE-INTEGRATION-1: the §26.4 object kind an AINumbers Evidence Envelope
// v0.1 receipt (research/EVIDENCE-ENVELOPE-V01-RATIFIED-2026-08-20.md, workspace-root
// AINumbers estate) travels in, DSSE-sealed like any other bundle object with
// predicate = { receipt, previous_receipt? }. Exported so hub/bundle.mjs's
// DEFAULT_TRUST_LABEL and any producer never hand-duplicate this string.
export const EVIDENCE_ENVELOPE_RECEIPT_KIND = "evidence_envelope_receipt";

const FORBIDDEN_FIELD_NAMES = new Set([
  "access_token", "refresh_token", "id_token", "secret", "secretKey", "privateKey",
  "password", "api_key", "raw_payload", "payload_bytes", "payload_body",
]);

// HELM-VERIFY-CLI-1: additive maxDepth param (default Infinity preserves the
// prior unbounded-recursion behavior for existing 2-arg callers, e.g. the
// browser Verify view). Confirmed by reading this function pre-patch: no
// depth guard existed here before this WU (phil's carried-forward open item,
// answered against the real code, not assumed).
function assertRedacted(obj, path = "$", depth = 0, maxDepth = Infinity) {
  if (depth > maxDepth) {
    throw new Error(`redaction check exceeded max depth ${maxDepth} at "${path}"`);
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => assertRedacted(v, `${path}[${i}]`, depth + 1, maxDepth));
    return;
  }
  if (obj && typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      if (FORBIDDEN_FIELD_NAMES.has(k)) {
        throw new Error(`"${path}.${k}" looks like a secret/raw payload and must not be exported`);
      }
      assertRedacted(v, `${path}.${k}`, depth + 1, maxDepth);
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
    // there is no Merkle-to-block-header proof yet to bind structurally. HELM-TSA-1
    // scope for OTS is exactly this: structural parse (does a pending_proof exist,
    // does its declared digest match) + an UPGRADE POINTER (the calendar URL the
    // reader can check later, themselves, for the Bitcoin block proof) — never a
    // live fetch here (SO #0: zero network in the blocking path).
    if (!anchor.pending_proof) return { checked: false, bound: null, reason: "no pending_proof bytes to inspect" };
    let bytes;
    try {
      bytes = base64ToBytes(anchor.pending_proof);
    } catch (err) {
      return { checked: true, bound: false, reason: `pending_proof is not valid base64: ${err.message}` };
    }
    if (bytes.length === 0) return { checked: true, bound: false, reason: "pending_proof is empty" };
    const anchoredHashHex = (anchor.anchored_hash ?? "").replace(/^sha256:/, "");
    const digestBound = anchoredHashHex === expectedHashHex;
    return {
      checked: true,
      bound: null, // never upgradeable to a definite verdict offline — see reason
      digestBound,
      upgradePointer: anchor.calendar ?? null,
      reason: digestBound
        ? "structural only: a pending calendar attestation is present and its declared digest matches this checkpoint. NOT yet a Bitcoin block proof (Phase 1 scope) — the upgrade pointer above is where a reader can check for that later, out of band."
        : "pending_proof's declared anchored_hash does not match this checkpoint's digest",
    };
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

// HELM-TSA-1: the FULL rfc3161 check (signature + chain-to-pinned-root +
// validity window, on top of verifyAnchorBinding's messageImprint check above).
// Deliberately SEPARATE from verifyAnchorBinding — that one stays synchronous
// and zero-crypto-lib so the initial verify pass renders instantly; this one
// dynamic-imports the pkijs bundle (~800KB, see ./rfc3161-verify.mjs) and is
// meant to be awaited as a progressive enhancement AFTER the first render, not
// blocking it. opentimestamps/queued/skipped anchors have no fuller check to
// run — delegates straight to verifyAnchorBinding for those.
export async function verifyAnchorFull(anchor, expectedHashHex) {
  if (anchor.type !== "rfc3161") return verifyAnchorBinding(anchor, expectedHashHex);
  if (!anchor.der && !anchor.proof) return { checked: false, bound: null, reason: "no proof bytes to bind" };
  const full = await verifyRfc3161Full(anchor.der ?? anchor.proof, expectedHashHex);
  return { checked: true, bound: full.messageImprint.bound, genTime: full.genTime, policyOid: full.policyOid, full };
}

// bundle: { manifest: {predicate, envelope}, objects: [{kind,digest,trust_label,envelope}], checkpoints: [{checkpointSeq,journalRootDigest,envelope}] }
// publicKeys: { ed25519SpkiB64, mldsa44B64 }
// Returns { valid, reasons[], detail } — never throws on a bad bundle (a
// tampered bundle is expected to come back { valid: false, reasons: [...] }).
export async function verifyBundle(bundle, publicKeys, opts = {}) {
  const { maxDepth = Infinity } = opts;
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
      assertRedacted(objResult.statement.predicate, "$", 0, maxDepth);
    } catch {
      reasons.push(`entry_redaction_violated:${entry.digest}`);
      detail.entries.push(row);
      continue;
    }
    row.valid = true;
    row.predicate = objResult.statement.predicate;
    // Additive: only an entry of this kind gets the extra check below; every other
    // kind's verdict is unchanged from before this row, so a pre-existing bundle
    // (no evidence_envelope_receipt entries) verifies byte-identically.
    if (entry.kind === EVIDENCE_ENVELOPE_RECEIPT_KIND) {
      const receiptResult = await verifyEvidenceEnvelopeReceipt(row.predicate.receipt, row.predicate.previous_receipt ?? null);
      row.evidence_envelope = receiptResult;
      if (!receiptResult.valid) {
        row.valid = false;
        reasons.push(`entry_evidence_envelope_invalid:${entry.digest}`);
      }
    }
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
