// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Matter store + CRUD (HELM-MATTER-H1, HELM-MATTER-BUILD-SPEC.md §2/§3). A
// matter is a Helm-local container binding one engagement (an exam, a
// filing, a dispute, an onboarding) — SQLite table on the SAME durability
// layer as HELM-H4 runs (D4: node:sqlite DatabaseSync, one process, one
// writer — see journal.mjs's header comment). Not an OCG chaingraph
// artifact, not submitted to SPEC.md; the manifest shape is the FROZEN
// schema/matter-manifest.schema.json (HELM-MATTER-S1, PR #216).
//
// bindings[] are a foreign-key-by-hash into ALREADY-SEALED local storage
// (§3) — never a payload copy, never re-executed, never re-signed. The
// load-bearing rule this module enforces (§2's bindings[].subject_kind
// description): every non-external_reference binding MUST resolve to a
// known local artifact before a matter is accepted, kind by kind:
//   run               -> hub/run.mjs's `runs` table, keyed by execution_hash
//   approval_record   -> hub/ha-store.mjs's `ha_records` table, keyed by
//                        record_id (itself a sha256:-prefixed JCS digest)
//   attested_artifact -> hub/run.mjs's `step_results` table. A chainless
//                        attested-artifact step's own execution_hash lives
//                        inside its memoized output shape (attested-
//                        artifact-runner.mjs's runAttestedArtifact), not in
//                        a dedicated column, so resolution scans the
//                        bounded set of `attested_artifacts:*` step outputs
//                        rather than adding a second index over a table
//                        this module does not own.
//   evidence_bundle   -> see EVIDENCE BUNDLE REGISTRY below.
//   external_reference is the ONLY kind exempt from resolution (§2) — it may
//   point at content Helm never verified, by design; never checked here.
//
// EVIDENCE BUNDLE REGISTRY: hub/bundle.mjs (HELM-H7) assembles evidence
// bundles ON DEMAND (assembleBundle/exportBundleZip) and they leave helmd as
// files (bundle.zip, via `helmd check` / the pq-export path) — verified
// against the shipped code at HELM-MATTER-H1 build time, there is no
// SQLite-persisted index of an assembled bundle's own manifest digest
// anywhere in helmd. A matter binding of kind evidence_bundle therefore has
// nothing to resolve against unless something registers the digest first.
// This module adds the minimal registry that makes resolution possible
// (`evidence_bundle_registry` + registerEvidenceBundle()) for a caller that
// has just locally assembled/exported one to record it. Wiring an automatic
// call from bundle.mjs's own assembler is deliberately left to a follow-up —
// this row's fence is the matter store + binding-resolution logic, not a
// change to HELM-H7's already-shipped, tested assembler.
import { randomBytes, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { initRunTables } from "./run.mjs";
import { initHaTables } from "./ha-store.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MATTER_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "schema", "matter-manifest.schema.json"), "utf8")
);

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32 — no I/L/O/U

// Zero-dep ULID (STANDING ORDERS #10 — never npm): 48-bit ms timestamp +
// 80 bits of crypto randomness, both Crockford base32 encoded, matching the
// schema's matter_id pattern ^[0-9A-HJKMNP-TV-Z]{26}$ exactly. Never derived
// from or colliding with any execution_hash (§2) — it carries no digest
// input at all, only wall-clock + randomness.
export function generateUlid(now = Date.now()) {
  let time = now;
  const timeChars = new Array(10);
  for (let i = 9; i >= 0; i--) {
    timeChars[i] = CROCKFORD[time % 32];
    time = Math.floor(time / 32);
  }
  const randBytes = randomBytes(10); // 80 bits
  let bits = "";
  for (const byte of randBytes) bits += byte.toString(2).padStart(8, "0");
  const randChars = new Array(16); // 80 bits / 5 bits-per-char = 16 chars
  for (let i = 0; i < 16; i++) {
    randChars[i] = CROCKFORD[parseInt(bits.slice(i * 5, i * 5 + 5), 2)];
  }
  return timeChars.join("") + randChars.join("");
}

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

// §2: "JCS digest ... of this manifest's own content with manifest_digest
// itself excluded from the preimage" — verified byte-for-byte against the
// HELM-MATTER-S1 golden fixture (fixtures/matter-manifest/golden.json) at
// build time.
export function computeManifestDigest(manifest) {
  const { manifest_digest, ...rest } = manifest;
  return `sha256:${jcsDigestHex(rest)}`;
}

export function initMatterTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS matters (
      matter_id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      manifest_json TEXT NOT NULL,
      manifest_digest TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_matters_status ON matters(status);
    CREATE TABLE IF NOT EXISTS evidence_bundle_registry (
      manifest_digest TEXT PRIMARY KEY,
      run_id TEXT,
      registered_at TEXT NOT NULL
    );
  `);
}

// Records a locally-assembled evidence bundle's own manifest digest (the
// bundle.mjs envelopeDigest(bundle.manifest.envelope) value — the same
// "sha256:<hex>" shape a matter binding's subject_hash carries) so a later
// matter can bind to it. Idempotent: registering the same digest twice is a
// no-op, never a duplicate row or an error.
export function registerEvidenceBundle(db, manifestDigest, { runId = null } = {}) {
  initMatterTables(db);
  db.prepare(
    "INSERT OR IGNORE INTO evidence_bundle_registry (manifest_digest, run_id, registered_at) VALUES (?, ?, ?)"
  ).run(manifestDigest, runId, new Date().toISOString());
}

function resolvesAsRun(db, subjectHash) {
  initRunTables(db);
  return !!db.prepare("SELECT 1 FROM runs WHERE execution_hash = ?").get(subjectHash);
}

function resolvesAsApprovalRecord(db, subjectHash) {
  initHaTables(db);
  return !!db.prepare("SELECT 1 FROM ha_records WHERE record_id = ?").get(subjectHash);
}

function resolvesAsEvidenceBundle(db, subjectHash) {
  initMatterTables(db);
  return !!db.prepare("SELECT 1 FROM evidence_bundle_registry WHERE manifest_digest = ?").get(subjectHash);
}

// attested_artifact bindings resolve against a memoized "attested_artifacts:*"
// step's OWN execution_hash — see the module header for why this scans
// step_results rather than a dedicated index. `artifact.execution_hash` is
// stored as BARE hex (attested-artifact-runner.mjs's jcsDigestHex, no
// "sha256:" prefix) — the same internal convention ha-gate.mjs's
// subjectHashFor/recordReplay/recordArtifactBindingVerification all follow
// (each adds the prefix at the point of comparison, never storing it
// prefixed), so this resolver prefixes before comparing rather than
// expecting the stored value to already carry it.
function resolvesAsAttestedArtifact(db, subjectHash) {
  initRunTables(db);
  const rows = db.prepare("SELECT output_json FROM step_results WHERE step_id LIKE 'attested_artifacts:%'").all();
  for (const row of rows) {
    let output;
    try {
      output = JSON.parse(row.output_json);
    } catch {
      continue;
    }
    const hex = output?.artifact?.execution_hash;
    if (hex && `sha256:${hex}` === subjectHash) return true;
  }
  return false;
}

const RESOLVERS = {
  run: resolvesAsRun,
  approval_record: resolvesAsApprovalRecord,
  evidence_bundle: resolvesAsEvidenceBundle,
  attested_artifact: resolvesAsAttestedArtifact,
};

// §2/§3's load-bearing rule: every non-external_reference binding MUST
// resolve to a known local artifact before it's accepted. Returns a list of
// human-readable errors (empty === every binding resolves); never throws —
// callers (createMatter/updateMatter) decide whether to reject.
export function unresolvedBindings(db, bindings) {
  const errors = [];
  for (const [i, binding] of (bindings ?? []).entries()) {
    if (binding.subject_kind === "external_reference") continue; // §2: the only exempt kind
    const resolver = RESOLVERS[binding.subject_kind];
    if (!resolver) {
      errors.push(`bindings[${i}]: unknown subject_kind "${binding.subject_kind}"`);
      continue;
    }
    if (!resolver(db, binding.subject_hash)) {
      errors.push(
        `bindings[${i}]: subject_hash "${binding.subject_hash}" (kind ${binding.subject_kind}) does not resolve to a known local artifact`
      );
    }
  }
  return errors;
}

export function validateMatterShape(manifest) {
  return validate(MATTER_SCHEMA, manifest);
}

// Creates a new matter. `input` carries the caller-supplied mutable fields
// (status?, entity, parties?, deadlines?, bindings?, narrative?) — matter_id,
// created_at, updated_at and manifest_digest are always server-assigned,
// never caller-supplied, so a client cannot mint a colliding or dishonest id
// or digest. Throws (never partially writes) on a schema violation or an
// unresolved binding.
export function createMatter(db, input = {}) {
  initMatterTables(db);
  const now = new Date().toISOString();
  const draft = {
    matter_id: generateUlid(),
    status: input.status ?? "intake",
    entity: input.entity,
    parties: input.parties ?? [],
    deadlines: input.deadlines ?? [],
    bindings: input.bindings ?? [],
    ...(input.narrative !== undefined ? { narrative: input.narrative } : {}),
    created_at: now,
    updated_at: now,
  };
  const manifest = { ...draft, manifest_digest: computeManifestDigest(draft) };

  const shapeErrors = validateMatterShape(manifest);
  if (shapeErrors.length) throw new Error(`matter-store: refused create — ${shapeErrors.join("; ")}`);

  const bindingErrors = unresolvedBindings(db, manifest.bindings);
  if (bindingErrors.length) throw new Error(`matter-store: refused create — ${bindingErrors.join("; ")}`);

  db.prepare(
    "INSERT INTO matters (matter_id, status, manifest_json, manifest_digest, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(manifest.matter_id, manifest.status, JSON.stringify(manifest), manifest.manifest_digest, manifest.created_at, manifest.updated_at);

  return manifest;
}

export function getMatter(db, matterId) {
  initMatterTables(db);
  const row = db.prepare("SELECT manifest_json FROM matters WHERE matter_id = ?").get(matterId);
  return row ? JSON.parse(row.manifest_json) : null;
}

export function listMatters(db, { status } = {}) {
  initMatterTables(db);
  const rows = status
    ? db.prepare("SELECT manifest_json FROM matters WHERE status = ? ORDER BY created_at ASC").all(status)
    : db.prepare("SELECT manifest_json FROM matters ORDER BY created_at ASC").all();
  return rows.map((r) => JSON.parse(r.manifest_json));
}

// Updates an existing matter. `patch` fields (status?, entity?, parties?,
// deadlines?, bindings?, narrative?) replace the corresponding member
// wholesale when present; an omitted field carries the existing value
// forward unchanged. matter_id and created_at never change; updated_at and
// manifest_digest are always recomputed. Re-validates the FULL resulting
// manifest against the §2 schema and re-runs §3 binding resolution — an
// update that would produce an invalid manifest or an unresolved binding is
// refused in full, never partially applied.
//
// §2 deadlines[] doc: "done:true records are append-only — never delete,
// never flip back to false." Enforced here by natural key (date, action,
// source): an update that would drop or un-done an already-done deadline is
// refused.
export function updateMatter(db, matterId, patch = {}) {
  initMatterTables(db);
  const existing = getMatter(db, matterId);
  if (!existing) throw new Error(`matter-store: unknown matter_id "${matterId}"`);

  const nextDeadlines = patch.deadlines ?? existing.deadlines;
  for (const prior of existing.deadlines) {
    if (!prior.done) continue;
    const stillDone = nextDeadlines.some(
      (d) => d.date === prior.date && d.action === prior.action && d.source === prior.source && d.done === true
    );
    if (!stillDone) {
      throw new Error(
        `matter-store: refused update — done:true deadline "${prior.action}" (${prior.date}) would be removed or un-done; deadlines are append-only`
      );
    }
  }

  const merged = {
    matter_id: existing.matter_id,
    status: patch.status ?? existing.status,
    entity: patch.entity ?? existing.entity,
    parties: patch.parties ?? existing.parties,
    deadlines: nextDeadlines,
    bindings: patch.bindings ?? existing.bindings,
    ...(("narrative" in patch ? patch.narrative !== undefined : existing.narrative !== undefined)
      ? { narrative: "narrative" in patch ? patch.narrative : existing.narrative }
      : {}),
    created_at: existing.created_at,
    updated_at: new Date().toISOString(),
  };
  const manifest = { ...merged, manifest_digest: computeManifestDigest(merged) };

  const shapeErrors = validateMatterShape(manifest);
  if (shapeErrors.length) throw new Error(`matter-store: refused update — ${shapeErrors.join("; ")}`);

  const bindingErrors = unresolvedBindings(db, manifest.bindings);
  if (bindingErrors.length) throw new Error(`matter-store: refused update — ${bindingErrors.join("; ")}`);

  db.prepare(
    "UPDATE matters SET status = ?, manifest_json = ?, manifest_digest = ?, updated_at = ? WHERE matter_id = ?"
  ).run(manifest.status, JSON.stringify(manifest), manifest.manifest_digest, manifest.updated_at, matterId);

  return manifest;
}

// Deletes a matter's local INDEX row only — a matter never holds primary
// evidence (§3: bindings are references, never payload copies), so deleting
// one cannot lose or alter any run/evidence-bundle/approval-record it
// pointed at. Returns false (never throws) for an unknown matter_id.
export function deleteMatter(db, matterId) {
  initMatterTables(db);
  const info = db.prepare("DELETE FROM matters WHERE matter_id = ?").run(matterId);
  return info.changes > 0;
}
