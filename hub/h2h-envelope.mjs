// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Helm-to-Helm bilateral exchange envelope (BILAT-H2H-BUILD-SPEC.md §2).
//
// Layer 0 ONLY: a file/bundle exchange format, transport-agnostic (email
// attachment, SFTP, USB, S3, shared git repo — the spec deliberately does not
// choose one, per §2.2). NO listener, NO daemon-to-daemon socket, NO
// AINumbers-operated network component of any kind (tripwire 4, §1). This
// module produces and consumes the `.helm-envelope` file's bytes; it never
// dials out.
//
// Built on hub/envelope.mjs's existing dual-signed (Ed25519 MUST, ML-DSA-44
// SHOULD) DSSE/in-toto emitter+verifier rather than a second signature
// scheme — the same primitive every other signed Helm object (manifest,
// checkpoint, attestation, evidence bundle manifest) already uses, so an
// H2H envelope is verifiable with the exact machinery a receiving Helm
// already ships.
//
// Run-input asymmetry (spec §4): `payload` is always a finished, signed
// artifact the sending org already produced and can stand behind — never a
// run input, never a request that the receiving side execute anything.
import { createHash } from "node:crypto";
import { buildStatement, emitEnvelope, verifyEnvelope, helmPredicateType } from "./envelope.mjs";

export const H2H_ENVELOPE_VERSION = "helm-h2h-envelope@1";
export const H2H_PREDICATE_TYPE = helmPredicateType("h2h_envelope_v1");

// Mirrors h2h_envelope.schema.json's payload_type enum. Kept in code (not
// re-derived from the schema file) so import can fail closed with no
// filesystem read on the hot path — see spec §5's "no partial parsing" rule.
export const KNOWN_PAYLOAD_TYPES = new Set([
  "matter_bundle",
  "counter_signed_receipt",
  "cosigned_checkpoint_head",
]);

// keys = { ed25519: { privateKey, publicKey }, mldsa44: { secretKey, publicKey } }
// (see keys.mjs generateKeys()/loadOrCreateKeys()) — the SENDING org's own
// signing keys. Returns the DSSE envelope object; write it as JSON to a
// `.helm-envelope` file by whatever transport the two orgs already trust.
export function exportH2HEnvelope({ senderOrgId, payloadType, payload }, keys) {
  if (!senderOrgId) throw new Error("h2h-envelope: senderOrgId is required");
  if (!KNOWN_PAYLOAD_TYPES.has(payloadType)) {
    throw new Error(`h2h-envelope: unknown payload_type "${payloadType}" — cannot emit an envelope this Helm couldn't later import`);
  }
  const predicate = {
    version: H2H_ENVELOPE_VERSION,
    sender_org_id: senderOrgId,
    payload_type: payloadType,
    payload,
  };
  const payloadDigest = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  const statement = buildStatement({
    subject: [{ name: senderOrgId, digest: { sha256: payloadDigest } }],
    predicateType: H2H_PREDICATE_TYPE,
    predicate,
  });
  return emitEnvelope(statement, keys);
}

// senderPublicKeys = the sender's public keys, ALREADY KNOWN to the receiving
// Helm out of band (spec §2.2 — this module holds no peer directory of its
// own; wiring a local peer trust store to this parameter is BILAT-H2H-CLI-1's
// job). Never throws — always returns a result the caller can act on,
// matching spec §5's fail-closed, plain-message, never-partial-ingest rule.
export function importH2HEnvelope(envelope, senderPublicKeys, { strict = false } = {}) {
  const verified = verifyEnvelope(envelope, senderPublicKeys, { strict });
  if (!verified.valid) {
    return {
      ok: false,
      reason: "signature",
      message: "Received an envelope whose signature does not verify — refusing to ingest. Ask the sender to re-send.",
    };
  }
  if (verified.statement.predicateType !== H2H_PREDICATE_TYPE) {
    return {
      ok: false,
      reason: "predicate_type",
      message: `Received a signed object that isn't a Helm-to-Helm exchange envelope (predicateType "${verified.statement.predicateType}") — refusing to ingest.`,
    };
  }

  const predicate = verified.statement.predicate;
  if (predicate?.version !== H2H_ENVELOPE_VERSION) {
    return {
      ok: false,
      reason: "version",
      message: `Received an envelope in a format this Helm doesn't understand (wire v${predicate?.version ?? "unknown"}, payload ${predicate?.payload_type ?? "unknown"}) — ask the sender which Helm version they're running.`,
    };
  }
  if (!KNOWN_PAYLOAD_TYPES.has(predicate.payload_type)) {
    return {
      ok: false,
      reason: "payload_type",
      message: `Received an envelope in a format this Helm doesn't understand (wire v${predicate.version}, payload ${predicate.payload_type}) — ask the sender which Helm version they're running.`,
    };
  }
  if (!predicate.sender_org_id) {
    return { ok: false, reason: "sender_org_id", message: "Received an envelope with no sender_org_id — refusing to ingest." };
  }

  return {
    ok: true,
    senderOrgId: predicate.sender_org_id,
    payloadType: predicate.payload_type,
    payload: predicate.payload,
  };
}
