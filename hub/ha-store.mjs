// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// §27.2 Human Accountability record store (HELM-HA-1). Records are shape-
// validated against the vendored $defs/humanAccountabilityRecord (the same
// schema fragment SPEC.md §27.2 defines — no second hand-rolled shape) and
// structurally signature-checked (isConformantEvidence) before being
// accepted; a record that fails either is refused, never stored half-valid.
//
// Separate from the OCG journal (D6): HA records are not run-execution
// transitions, they are accountability evidence ABOUT a subject_hash — SCITT
// statements-about-statements (§27.0). One SQLite table, keyed by a caller
// -supplied record_id (the record's own JCS digest, so a resubmission of the
// identical record is a no-op, not a duplicate).
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { isConformantEvidence } from "./vendored/ocg/kernels/_hagate.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDORED_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "vendored", "ocg", "openchain-graph-v0.4.schema.json"), "utf8")
);
const HA_RECORD_SCHEMA = VENDORED_SCHEMA.$defs.humanAccountabilityRecord;

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

export function initHaTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS ha_records (
      record_id TEXT PRIMARY KEY,
      subject_hash TEXT NOT NULL,
      record_type TEXT NOT NULL,
      role TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      record_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ha_records_subject_idx ON ha_records (subject_hash);
    CREATE TABLE IF NOT EXISTS ha_countersignature_slots (
      subject_hash TEXT PRIMARY KEY,
      slot_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);
}

// Shape (schema §27.2) + structural signature (§16 eddsa-jcs-2022 bound to
// identity.id) checks — NOT cryptographic verification (that needs the
// resolved public key; see ha-gate.mjs verifyHaRecordSignature, which callers
// MUST run before appendHaRecord for any record not minted by helmd itself).
//
// $defs/humanAccountabilityRecord describes the shape of an output_payload
// (audit_signature lives on the wrapping $defs/artifact envelope, sibling to
// output_payload, hence NOT in this $def's properties list under its
// additionalProperties:false). Every real consumer — the vendored
// _hagate.mjs evaluator AND its own fixtures.json — instead uses the FLAT
// convention (record_type/role/subject_hash/identity/audit_signature all
// siblings on one object), so that's what this store persists too;
// audit_signature is stripped before the schema check and verified
// separately via isConformantEvidence below.
export function validateHaRecordShape(record) {
  const { audit_signature, ...shapeOnly } = record ?? {};
  const errs = validate(HA_RECORD_SCHEMA, shapeOnly, VENDORED_SCHEMA);
  if (errs.length) return { ok: false, errors: errs };
  if (!isConformantEvidence(record)) {
    return { ok: false, errors: ["record carries no conformant §27.2 signed-named-human proof (audit_signature.proof missing/mismatched)"] };
  }
  return { ok: true, errors: [] };
}

// Idempotent: appending the identical record twice (same JCS bytes) is a
// no-op, keyed by the record's own digest rather than a caller-chosen id.
export function appendHaRecord(db, record) {
  initHaTables(db);
  const shapeCheck = validateHaRecordShape(record);
  if (!shapeCheck.ok) throw new Error(`ha-store: refused record — ${shapeCheck.errors.join("; ")}`);
  const recordId = `sha256:${jcsDigestHex(record)}`;
  db.prepare(
    `INSERT OR IGNORE INTO ha_records (record_id, subject_hash, record_type, role, identity_id, record_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(recordId, record.subject_hash, record.record_type, record.role, record.identity.id, JSON.stringify(record), new Date().toISOString());
  return { recordId, record };
}

export function recordsForSubject(db, subjectHash) {
  initHaTables(db);
  return db
    .prepare("SELECT record_json FROM ha_records WHERE subject_hash = ? ORDER BY created_at ASC")
    .all(subjectHash)
    .map((row) => JSON.parse(row.record_json));
}

// Fetches one record by its own record_id (the table's primary key — the
// record's own JCS digest, per the module header). Distinct from
// recordsForSubject above (which answers "what targets this subject_hash"):
// HELM-MATTER-H2's matter closeout export needs "the approval record itself"
// for an approval_record binding, whose subject_hash IS a record_id
// (matter-store.mjs's resolvesAsApprovalRecord resolves the same way).
export function getRecordById(db, recordId) {
  initHaTables(db);
  const row = db.prepare("SELECT record_json FROM ha_records WHERE record_id = ?").get(recordId);
  return row ? JSON.parse(row.record_json) : null;
}

export function allHaRecords(db) {
  initHaTables(db);
  return db.prepare("SELECT record_json FROM ha_records ORDER BY created_at ASC").all().map((row) => JSON.parse(row.record_json));
}

// countersignature_slot (schema/countersignature_slot.schema.json) — helmd's
// own §27.3 maker-checker bundle for a subject, distinct from the generic HA
// record trail above: this is the artifact-level structure whose
// `countersignatures[].replay_verified` flag is the flagship "checker
// independently re-ran the workflow and matched" claim (ha-gate.mjs
// recordReplay is the ONLY writer of a true value into this store).
export function getOrInitSlot(db, subjectHash, makerSignature) {
  initHaTables(db);
  const row = db.prepare("SELECT slot_json FROM ha_countersignature_slots WHERE subject_hash = ?").get(subjectHash);
  if (row) return JSON.parse(row.slot_json);
  const slot = { bundle_digest: subjectHash, maker_signature: makerSignature, countersignatures: [] };
  db.prepare(
    "INSERT INTO ha_countersignature_slots (subject_hash, slot_json, updated_at) VALUES (?, ?, ?)"
  ).run(subjectHash, JSON.stringify(slot), new Date().toISOString());
  return slot;
}

export function getSlot(db, subjectHash) {
  initHaTables(db);
  const row = db.prepare("SELECT slot_json FROM ha_countersignature_slots WHERE subject_hash = ?").get(subjectHash);
  return row ? JSON.parse(row.slot_json) : null;
}

// HELM-MAKERCHECKER-BUILD-SPEC.md MC-1.2: the explicit maker act. Prior to
// this, NOTHING in production ever called getOrInitSlot with a real
// makerSignature — every recordReplay/recordArtifactBindingVerification call
// therefore hit MC-1.1's fail-closed refusal (§0.6's "genuinely missing"
// piece). This is that producer: a caller (ha-gate.mjs submitMakerSignature,
// after cryptographic verification) supplies a signature the maker minted
// themselves over the subject digest — never inferred from run ownership,
// the first record filed, or the daemon's identity (MC-1.2's own MUST NOTs).
//
// Idempotent for a re-submission of the SAME maker (same keyid): a maker
// re-signing after a restart is not an error. A DIFFERENT keyid is refused —
// an examiner reading a slot must never see its maker silently swapped.
export function setMakerSignature(db, subjectHash, makerSignature) {
  initHaTables(db);
  const keyid = makerSignature?.keyid;
  if (!keyid) throw new Error("ha-store: refused maker signature — no keyid (MC-1.2: an explicit act needs a resolvable identity)");
  const existing = getOrInitSlot(db, subjectHash, null);
  if (existing.maker_signature?.keyid && existing.maker_signature.keyid !== keyid) {
    throw new Error(
      "ha-store: refused maker signature — slot already has a maker_signature under a different keyid (a maker is never silently swapped)"
    );
  }
  const slot = { ...existing, maker_signature: makerSignature };
  db.prepare(
    "UPDATE ha_countersignature_slots SET slot_json = ?, updated_at = ? WHERE subject_hash = ?"
  ).run(JSON.stringify(slot), new Date().toISOString(), subjectHash);
  return slot;
}

// HELM-MAKERCHECKER-BUILD-SPEC.md §2 verdict: ONE shared predicate for
// distinct-human-checker counting, called from both the store (here, for
// pinning E-6/E-7) and the gate layer (ha-gate.mjs's evidence read-outs) — no
// second canon. Would live in the vendored _hagate.mjs beside
// distinctApprovers per FU-4, but this row's fence forbids a vendored edit;
// this is the one shared home available inside it.
//
// MC-1.3: distinctness is by identity.id alone (two entries from the same
// identity, any signed_at, count once). MC-2.2: only attester_kind:"human"
// counts toward a threshold — an "automated" entry stays stored and readable
// (it is genuine, valuable machine evidence) but never counts.
export function distinctHumanCheckerIds(countersignatures) {
  const ids = new Set();
  for (const c of countersignatures ?? []) {
    if (c?.attester_kind === "human" && c?.identity?.id) ids.add(c.identity.id);
  }
  return ids;
}

// E-6/E-7: a slot is read as *satisfied*, not merely *populated*, only once
// the threshold in force and the moment of determination are PINNED onto it
// — a threshold read from live policy at examination time answers a
// different question than the one the examiner asked (§4). Pinning is
// write-once (MC-7's additive-only spirit applied to satisfaction state): a
// slot already pinned keeps its original threshold/as_of even if a later
// call passes a different requiredThreshold or more checkers arrive.
export function pinSlotSatisfaction(db, subjectHash, { requiredThreshold, nowISO }) {
  initHaTables(db);
  const slot = getSlot(db, subjectHash);
  if (!slot) return null;
  if (slot.threshold != null && slot.as_of) return slot; // already pinned — immutable
  const distinctCount = distinctHumanCheckerIds(slot.countersignatures).size;
  if (distinctCount < requiredThreshold) return slot; // not yet satisfied — nothing to pin
  const pinned = { ...slot, threshold: requiredThreshold, as_of: nowISO };
  db.prepare(
    "UPDATE ha_countersignature_slots SET slot_json = ?, updated_at = ? WHERE subject_hash = ?"
  ).run(JSON.stringify(pinned), new Date().toISOString(), subjectHash);
  return pinned;
}

// Appends one countersignature to an existing (or lazily-created, makerless)
// slot. `countersignature.replay_verified` is trusted here as-given — the
// caller (ha-gate.mjs recordReplay) is the ONLY code path permitted to set it
// true, having already done the real re-execution; this function just stores
// what it's handed.
//
// HELM-MAKERCHECKER-BUILD-SPEC.md MC-1/MC-1.1: refuses (throws, never
// persists) rather than silently admitting a countersignature that cannot be
// proven distinct from the maker. This is the fix for the hole quoted in
// that spec's §0.2 — the old predicate below compared checkers against each
// other only, never against the maker, so one keypair satisfied both roles.
export function addCountersignature(db, subjectHash, countersignature, { makerSignature = null } = {}) {
  initHaTables(db);
  const slot = getOrInitSlot(db, subjectHash, makerSignature);

  // MC-1.1: absence of a maker identity is a REFUSAL, never a pass. Every
  // slot minted before a maker_signature producer exists has
  // maker_signature:null — comparing a checker id against null would admit
  // everything, so an unresolvable comparison fails closed instead.
  const makerKeyid = slot.maker_signature?.keyid;
  if (!makerKeyid) {
    throw new Error(
      "ha-store: refused countersignature — slot has no maker_signature.keyid to compare against (MC-1.1: absence of a maker is a refusal, never a pass)"
    );
  }

  // MC-1: same-identity countersignature is forbidden. Exact did:key string
  // comparison, case-sensitive, trimmed only — no other normalisation.
  const checkerId = (countersignature?.identity?.id ?? "").trim();
  if (checkerId && checkerId === makerKeyid.trim()) {
    throw new Error(
      "ha-store: refused countersignature — checker identity equals the slot's maker identity (MC-1: same-identity countersignature forbidden)"
    );
  }

  // MC-2.1: every countersignature MUST carry an explicit attester_kind,
  // recorded at signing time by the producer — never inferred by a reader
  // from key location, key type, or endpoint. A countersignature with no
  // stated kind is refused rather than silently treated as either.
  if (countersignature?.attester_kind !== "human" && countersignature?.attester_kind !== "automated") {
    throw new Error(
      "ha-store: refused countersignature — no explicit attester_kind of \"human\" or \"automated\" (MC-2.1)"
    );
  }

  // MC-1.3: distinctness among checkers is by identity.id ALONE. Two acts by
  // the same identity at different signed_at are both retained here (an
  // audit trail of two acts, permitted) — only an exact-duplicate
  // resubmission (identical identity.id AND signed_at) is a no-op. Counting
  // toward a threshold, wherever that happens, must collapse same-identity
  // entries to one regardless of signed_at; this function does not count.
  const already = slot.countersignatures.some(
    (c) => c.identity?.id === countersignature.identity?.id && c.signed_at === countersignature.signed_at
  );
  if (!already) slot.countersignatures.push(countersignature);
  db.prepare(
    "UPDATE ha_countersignature_slots SET slot_json = ?, updated_at = ? WHERE subject_hash = ?"
  ).run(JSON.stringify(slot), new Date().toISOString(), subjectHash);
  return slot;
}

export { HA_RECORD_SCHEMA, VENDORED_SCHEMA };
