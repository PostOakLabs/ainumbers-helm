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
import { initRunTables, buildRunEvidenceExportPayload } from "./run.mjs";
import { initHaTables, getRecordById } from "./ha-store.mjs";
import { buildStatement, emitEnvelope, helmPredicateType } from "./envelope.mjs";

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
    CREATE TABLE IF NOT EXISTS matter_exports (
      matter_id TEXT PRIMARY KEY,
      export_json TEXT NOT NULL,
      envelope_digest TEXT NOT NULL,
      created_at TEXT NOT NULL
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
// Returns the matching step's memoized output — the §27.4 {tool_ref,
// inputs_digest, artifact} triple HELM-MATTER-H2's closeout export ships
// verbatim for an attested_artifact binding — or null if none resolves.
// resolvesAsAttestedArtifact below is a thin boolean wrapper over this: one
// implementation of "which attested_artifacts:* step matches this hash",
// not two.
export function findAttestedArtifact(db, subjectHash) {
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
    if (hex && `sha256:${hex}` === subjectHash) return output;
  }
  return null;
}

function resolvesAsAttestedArtifact(db, subjectHash) {
  return findAttestedArtifact(db, subjectHash) !== null;
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

// ---------------------------------------------------------------------------
// §5 closeout export (HELM-MATTER-H2). "assembling a matter export means
// walking bindings[], pulling each referenced artifact from local storage
// ... and packaging them alongside the matter manifest itself — never
// re-fetching, re-executing, or re-signing anything already sealed" (§3's
// export-path consequence). Every helper below pulls from a table this
// module (or ha-store.mjs/run.mjs) already owns; nothing here re-derives an
// execution_hash or mints a competing signature over content that already
// has one.
//
// SCOPING NOTE on `evidence_bundle` bindings, stated plainly rather than
// silently under-delivered: §5's design text describes "a §27.6 evidence
// bundle" as the export form for both `run` and `evidence_bundle` bindings.
// helmd has never persisted an assembled bundle's PAYLOAD anywhere — this
// module's own header comment (H1) already established that bundle.mjs's
// assembleBundle/exportBundleZip leave helmd as files, and evidence_bundle_
// registry (H1) deliberately stores only {manifest_digest, run_id,
// registered_at}, never the bundle body. There is therefore no already-
// shipped bundle PAYLOAD anywhere in local storage to re-attach for an
// `evidence_bundle` binding — inventing one at export time would mean
// assembling+signing a bundle that was never sealed before, which is new
// signing capability outside this row's fence, not reuse of an existing
// export form. What IS already-shipped and already-local for an
// `evidence_bundle` binding is the registry entry itself (proof the digest
// was locally registered, with its timestamp) plus — where the registry
// names the run_id that produced it — that run's own already-shipped
// digest-level record (the exact `run` case below). That is what ships.
function runIdForExecutionHash(db, executionHash) {
  initRunTables(db);
  const row = db.prepare("SELECT run_id FROM runs WHERE execution_hash = ?").get(executionHash);
  return row ? row.run_id : null;
}

// Pulls one binding's own already-shipped export form from local storage, or
// throws if it no longer resolves (it was accepted at create/update time,
// per §2/§3's validation gate, but nothing prevents local storage from being
// pruned between then and a later export — this module never silently ships
// a hole). external_reference never reaches local storage by design (§2) —
// it is labeled distinctly (never collapsed into "verified"), same §26.6
// trust-label discipline the matter manifest itself follows.
function exportBindingArtifact(db, binding) {
  const { subject_hash, subject_kind, note } = binding;
  const base = { subject_hash, subject_kind, ...(note !== undefined ? { note } : {}) };

  if (subject_kind === "external_reference") {
    return { ...base, exported: false, reason: "external_reference — hashed but never verified by Helm; nothing local to export (§2)" };
  }
  if (subject_kind === "run") {
    const runId = runIdForExecutionHash(db, subject_hash);
    const artifact = runId ? buildRunEvidenceExportPayload(db, runId) : null;
    if (!artifact) throw new Error(`matter-store: export refused — run binding "${subject_hash}" no longer resolves`);
    return { ...base, exported: true, artifact };
  }
  if (subject_kind === "approval_record") {
    const artifact = getRecordById(db, subject_hash);
    if (!artifact) throw new Error(`matter-store: export refused — approval_record binding "${subject_hash}" no longer resolves`);
    return { ...base, exported: true, artifact };
  }
  if (subject_kind === "attested_artifact") {
    const artifact = findAttestedArtifact(db, subject_hash);
    if (!artifact) throw new Error(`matter-store: export refused — attested_artifact binding "${subject_hash}" no longer resolves`);
    return { ...base, exported: true, artifact };
  }
  if (subject_kind === "evidence_bundle") {
    initMatterTables(db);
    const row = db.prepare("SELECT run_id, registered_at FROM evidence_bundle_registry WHERE manifest_digest = ?").get(subject_hash);
    if (!row) throw new Error(`matter-store: export refused — evidence_bundle binding "${subject_hash}" no longer resolves`);
    const runArtifact = row.run_id ? buildRunEvidenceExportPayload(db, row.run_id) : null;
    return {
      ...base,
      exported: true,
      artifact: { registered_at: row.registered_at, run_id: row.run_id ?? null, ...(runArtifact ? { run_evidence: runArtifact } : {}) },
    };
  }
  throw new Error(`matter-store: export refused — unknown subject_kind "${subject_kind}"`);
}

// ---------------------------------------------------------------------------
// §5.1/§5.2 (amendment 2026-08-20): two export flavours derived from the SAME
// directory-rooted manifest as the evidence-bundle-of-bundles above, emitted
// from the SAME closeout path (assembleMatterExport below) and signed via the
// SAME DSSE envelope — zero new signing code (spec §0: "reuses existing
// bundle signing"). Citations:
//   §5.1 — research/clause-snapshots/CTJ-general-guidance-electronic-court-
//          bundles-2021-11-29.citations.md (paragraph numbers cited inline).
//   §5.2 — research/clause-snapshots/EDRM-production-standards-v2.citations.md.
// Naming note (spec §0): the row's own naming shorthand calls this anchor
// "CPR PD 5C" — that is WRONG per the pinned snapshot's own "Note on the
// anchor label": PD 5C only governs CE-File format, not pagination/bookmark
// rules. The paragraph numbers cited below are the CTJ General Guidance,
// never PD 5C.

function pdfEscape(str) {
  return String(str).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)").replace(/[\r\n]/g, " ");
}

// CTJ ¶2: "computer-generated numbering ... start at page 1 ... sequentially
// to the last page ... pagination matches the pdf numbering."
function paginationOps(pageNum, totalPages) {
  return `BT /F1 8 Tf 1 0 0 1 500 30 Tm (Page ${pageNum} of ${totalPages}) Tj ET\n`;
}

function textOpsForLines(lines, { startY = 740, leading = 16, x = 56, fontSize = 10 } = {}) {
  let ops = `BT /F1 ${fontSize} Tf ${leading} TL 1 0 0 1 ${x} ${startY} Tm\n`;
  lines.forEach((line, i) => {
    if (i > 0) ops += "T*\n";
    ops += `(${pdfEscape(String(line))}) Tj\n`;
  });
  ops += "ET\n";
  return ops;
}

function streamObj(content) {
  return `<< /Length ${Buffer.byteLength(content, "latin1")} >>\nstream\n${content}\nendstream`;
}

// Serializes an array of already-built PDF object bodies (1-indexed by
// position) into a complete PDF-1.7 file with a real xref table — no
// external PDF library (CONTRACT-equivalent zero-dep discipline, mirrored
// here for the helm repo's own zero-dep package.json).
function buildPdf(objs, rootObjNum) {
  let out = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n";
  const offsets = [0];
  objs.forEach((body, idx) => {
    offsets.push(Buffer.byteLength(out, "latin1"));
    out += `${idx + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xrefStart = Buffer.byteLength(out, "latin1");
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i <= objs.length; i++) out += `${String(offsets[i]).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root ${rootObjNum} 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(out, "latin1");
}

// §5.1: a single, paginated, bookmarked PDF index over bindings_export — one
// bookmarked, hyperlinked-from-index page per binding (CTJ ¶3), plus a cover
// page surfacing every open deadline unredacted (§1 CounselOS addition, not
// CTJ-sourced). Native text throughout (never scanned), so it inherently
// carries a text layer without needing OCR (CTJ ¶4). Default zoom 100% via
// /OpenAction ... /XYZ null null 1 (CTJ ¶6). No images anywhere, so the ¶9
// dpi/file-size provisions are satisfied trivially (nothing to compress).
// This is a navigation aid over already-verified bindings, never itself the
// thing verified — §4's verify page verifies bindings[]/the DSSE envelope,
// not this PDF's own bytes.
export function buildEBundlePdf(matter, bindingsExport) {
  const N = bindingsExport.length;
  const totalPages = 1 + N;
  const objs = [];
  function addObj(body) {
    objs.push(body);
    return objs.length;
  }

  const catalogNum = addObj("");
  const pagesNum = addObj("");
  const fontNum = addObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");

  const pageNums = [];
  const contentNums = [];
  for (let k = 0; k < totalPages; k++) {
    pageNums.push(addObj(""));
    contentNums.push(addObj(""));
  }

  const startY = 740;
  const leading = 16;
  const xLeft = 56;
  const fontSize = 10;

  // Cover/index page — open deadlines surfaced first (§1 CounselOS addition),
  // then one hyperlinked line per binding (CTJ ¶3).
  const openDeadlines = (matter.deadlines ?? []).filter((d) => !d.done);
  const indexLines = [`MATTER E-BUNDLE INDEX — ${matter.matter_id}`, `Entity: ${matter.entity?.id ?? ""}`, ""];
  if (openDeadlines.length) {
    indexLines.push(`OPEN DEADLINES (${openDeadlines.length}) — unredacted:`);
    openDeadlines.forEach((d) => indexLines.push(`  - ${d.date} ${d.action} (${d.type})`));
  } else {
    indexLines.push("No open deadlines.");
  }
  indexLines.push("", `INDEX (${N} binding${N === 1 ? "" : "s"}):`);
  const entryStartLine = indexLines.length;
  bindingsExport.forEach((b, i) => indexLines.push(`  ${i + 1}. ${b.subject_kind} - ${b.subject_hash}  (p.${i + 2})`));

  objs[contentNums[0] - 1] = streamObj(textOpsForLines(indexLines, { startY, leading, x: xLeft, fontSize }) + paginationOps(1, totalPages));

  const annotNums = bindingsExport.map((b, i) => {
    const y = startY - (entryStartLine + i) * leading;
    const rect = `${xLeft} ${y - 3} ${xLeft + 500} ${y + 10}`;
    return addObj(`<< /Type /Annot /Subtype /Link /Rect [${rect}] /Border [0 0 0] /Dest [${pageNums[i + 1]} 0 R /XYZ null null null] >>`);
  });

  objs[pageNums[0] - 1] =
    `<< /Type /Page /Parent ${pagesNum} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontNum} 0 R >> >> ` +
    `/Contents ${contentNums[0]} 0 R` +
    (annotNums.length ? ` /Annots [${annotNums.map((n) => `${n} 0 R`).join(" ")}]` : "") +
    ` >>`;

  // One page per binding.
  bindingsExport.forEach((b, i) => {
    const pageIdx = i + 1;
    const lines = [`BINDING ${i + 1} of ${N}`, `subject_kind: ${b.subject_kind}`, `subject_hash: ${b.subject_hash}`, `exported: ${b.exported ? "yes" : "no"}`];
    if (b.note) lines.push(`note: ${b.note}`);
    if (!b.exported && b.reason) lines.push(`reason: ${b.reason}`);
    objs[contentNums[pageIdx] - 1] = streamObj(textOpsForLines(lines, { startY, leading, x: xLeft, fontSize }) + paginationOps(pageIdx + 1, totalPages));
    objs[pageNums[pageIdx] - 1] =
      `<< /Type /Page /Parent ${pagesNum} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontNum} 0 R >> >> /Contents ${contentNums[pageIdx]} 0 R >>`;
  });

  // Bookmarks — one per page, text includes the page number (CTJ ¶3).
  const outlineItemNums = pageNums.map(() => addObj(""));
  const outlinesRootNum = addObj("");
  outlineItemNums.forEach((num, k) => {
    const title = k === 0 ? "Index (p.1)" : `${bindingsExport[k - 1].subject_kind} - ${bindingsExport[k - 1].subject_hash.slice(0, 24)}... (p.${k + 1})`;
    const prev = k > 0 ? outlineItemNums[k - 1] : null;
    const next = k < outlineItemNums.length - 1 ? outlineItemNums[k + 1] : null;
    objs[num - 1] =
      `<< /Title (${pdfEscape(title)}) /Parent ${outlinesRootNum} 0 R ` +
      (prev ? `/Prev ${prev} 0 R ` : "") +
      (next ? `/Next ${next} 0 R ` : "") +
      `/Dest [${pageNums[k]} 0 R /XYZ null null null] >>`;
  });
  objs[outlinesRootNum - 1] = `<< /Type /Outlines /First ${outlineItemNums[0]} 0 R /Last ${outlineItemNums[outlineItemNums.length - 1]} 0 R /Count ${outlineItemNums.length} >>`;

  objs[pagesNum - 1] = `<< /Type /Pages /Kids [${pageNums.map((n) => `${n} 0 R`).join(" ")}] /Count ${pageNums.length} >>`;
  // CTJ ¶6: default view/zoom 100% — /XYZ null null 1.
  objs[catalogNum - 1] =
    `<< /Type /Catalog /Pages ${pagesNum} 0 R /Outlines ${outlinesRootNum} 0 R /PageMode /UseOutlines /OpenAction [${pageNums[0]} 0 R /XYZ null null 1] >>`;

  return buildPdf(objs, catalogNum);
}

// CTJ "Filename" rule (p.4): case reference + content indicator. `regime`
// isn't a field the shipped S1 schema carries (spec §2 describes it, S1's
// actual JSON Schema does not — pre-existing divergence, out of this row's
// fence to fix), so matter_id is the only case reference available.
export function eBundlePdfFilename(matter) {
  return `${matter.matter_id}-e-bundle.pdf`;
}

// §5.2: EDRM's own 24-field metadata/load-file list (pinned
// EDRM-production-standards-v2.citations.md, verbatim field order), one row
// per bindings_export entry. Only fields with a real matter-side source are
// populated (per the spec's own mapping table); the rest are emitted
// present-but-empty, never fabricated.
const EDRM_FIELDS = [
  "ATTACHMENTIDS", "AUTHORS", "BATES RANGE", "BCC", "CC", "CUSTODIAN", "DATECREATED",
  "DATERECEIVED", "DATESAVED", "DATESENT", "DOCEXT", "DOCID", "DOCLINK", "FILENAME",
  "FOLDER", "FROM", "HASH", "PARENTID", "RCRDTYPE", "SUBJECT", "THREAD ID",
  "TIMERECEIVED", "TIMESENT", "TO",
];
// Concordance-style pilcrow/thorn/caret delimiters are documented industry
// tooling convention, NOT EDRM primary text (pinned citations file, "Note on
// delimiter characters") — used here as the de facto interchange convention
// and stated as such, never misattributed to an EDRM paragraph that doesn't
// exist for the delimiter bytes.
const DAT_FIELD_SEP = "\u00b6";
const DAT_TEXT_QUALIFIER = "\u00fe";

function datQuote(value) {
  return `${DAT_TEXT_QUALIFIER}${String(value ?? "")}${DAT_TEXT_QUALIFIER}`;
}

export function buildEdrmDat(matter, bindingsExport) {
  const rows = bindingsExport.map((b, i) => {
    const artifact = b.artifact;
    return {
      ATTACHMENTIDS: "", AUTHORS: "", "BATES RANGE": "", BCC: "", CC: "",
      CUSTODIAN: matter.entity?.id ?? "",
      DATECREATED: artifact?.created_at ?? artifact?.recorded_at ?? "",
      DATERECEIVED: "", DATESAVED: "", DATESENT: "", DOCEXT: "",
      DOCID: b.subject_hash,
      DOCLINK: `${matter.matter_id}/bindings/${i}`,
      FILENAME: `${matter.matter_id}/bindings/${i}`,
      FOLDER: "", FROM: "",
      HASH: b.subject_hash,
      PARENTID: artifact?.parent_subject_hash ?? "",
      RCRDTYPE: b.subject_kind,
      SUBJECT: "", "THREAD ID": "", TIMERECEIVED: "", TIMESENT: "", TO: "",
    };
  });
  const header = EDRM_FIELDS.map(datQuote).join(DAT_FIELD_SEP);
  const lines = rows.map((row) => EDRM_FIELDS.map((f) => datQuote(row[f])).join(DAT_FIELD_SEP));
  return [header, ...lines].join("\r\n") + "\r\n";
}

export function edrmDatFilename(matter) {
  return `${matter.matter_id}.dat`;
}

// Assembles the signed bundle-of-bundles: the matter manifest plus every
// non-external_reference binding's own export form, wrapped in ONE DSSE
// envelope (envelope.mjs's already-shipped emitEnvelope — the same
// mechanism every other signed Helm object uses; helmPredicateType's own
// prefix scheme is open-vocabulary, so "matter_export" needs no schema/enum
// change anywhere). Selective disclosure is NOT re-invented here — each
// artifact that already carries a §13.12/§26.6 redaction/trust-label
// mechanism keeps it untouched; this function only aggregates and signs the
// aggregate, it does not redact anything itself.
//
// §5.1/§5.2 (amendment): both export flavours are built from the SAME
// bindings_export this function already assembles and folded into the SAME
// predicate, so they ride the SAME DSSE envelope as the rest of the closeout
// export — no second signature, no second call site.
export function assembleMatterExport(db, matterId, { keys } = {}) {
  if (!keys) throw new Error("matter-store: assembleMatterExport requires signing keys");
  const matter = getMatter(db, matterId);
  if (!matter) throw new Error(`matter-store: unknown matter_id "${matterId}"`);
  if (matter.status !== "closed") {
    throw new Error(`matter-store: refused export — matter "${matterId}" is not closed (status: "${matter.status}")`);
  }

  const bindings_export = (matter.bindings ?? []).map((b) => exportBindingArtifact(db, b));

  const predicate = {
    matter_id: matter.matter_id,
    matter_manifest_digest: matter.manifest_digest,
    exported_at: new Date().toISOString(),
    bindings_export,
    e_bundle_pdf_base64: buildEBundlePdf(matter, bindings_export).toString("base64"),
    e_bundle_pdf_filename: eBundlePdfFilename(matter),
    edrm_dat_text: buildEdrmDat(matter, bindings_export),
    edrm_dat_filename: edrmDatFilename(matter),
  };
  const statement = buildStatement({
    subject: [{ name: "matter_manifest", digest: { sha256: matter.manifest_digest.replace(/^sha256:/, "") } }],
    predicateType: helmPredicateType("matter_export"),
    predicate,
  });
  const envelope = emitEnvelope(statement, keys);

  return { matter, predicate, envelope };
}

function matterExportEnvelopeDigest(envelope) {
  const statement = JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
  return `sha256:${jcsDigestHex(statement)}`;
}

// Persists the just-assembled export (matter_exports, keyed one-per-matter —
// see closeMatter below for why this is only ever called once per closure)
// and returns the shape the REST/CLI/MCP surfaces hand back verbatim.
function persistMatterExport(db, matterId, assembled) {
  initMatterTables(db);
  const envelopeDigest = matterExportEnvelopeDigest(assembled.envelope);
  const createdAt = new Date().toISOString();
  const record = { matter_id: matterId, manifest: assembled.matter, predicate: assembled.predicate, envelope: assembled.envelope };
  db.prepare(
    "INSERT OR REPLACE INTO matter_exports (matter_id, export_json, envelope_digest, created_at) VALUES (?, ?, ?, ?)"
  ).run(matterId, JSON.stringify(record), envelopeDigest, createdAt);
  return { ...record, envelope_digest: envelopeDigest, created_at: createdAt };
}

// Reads back a matter's closure export, or null if the matter has never been
// closed (or was closed with no signing keys available — see closeMatter).
// Never recomputes/re-signs — this is a pure read of what closeMatter
// already persisted at the moment of closure.
export function getMatterExport(db, matterId) {
  initMatterTables(db);
  const row = db.prepare("SELECT export_json, envelope_digest, created_at FROM matter_exports WHERE matter_id = ?").get(matterId);
  if (!row) return null;
  return { ...JSON.parse(row.export_json), envelope_digest: row.envelope_digest, created_at: row.created_at };
}

// The §5 closeout hook itself, as one call: applies `patch` via the
// existing, untouched updateMatter — this function adds to that code path,
// it does not alter it — and, ONLY if THIS call is what actually transitions
// status into "closed" (the matter's prior status was something else), also
// assembles and persists the signed export automatically, same call, no
// separate step (SO #0b: automate over remind). A later edit to an
// already-closed matter (prior status already "closed") never re-emits —
// the closure export is signed exactly once, not re-signed on every
// subsequent edit. `keys` omitted (undefined) is legal: the status change
// still applies in full, simply with no export — server.mjs's real routes
// always supply identityKeys, so this only matters for a direct library
// caller that doesn't care about the export (e.g. existing tests predating
// this row, unaffected since they never invoke this function).
//
// Returns { matter, export }, where `export` is present (the persistMatter
// Export shape) only when this call just emitted one.
export function closeMatter(db, matterId, patch, keys) {
  const before = getMatter(db, matterId);
  const matter = updateMatter(db, matterId, patch);
  let exportResult;
  if (matter.status === "closed" && before?.status !== "closed" && keys) {
    const assembled = assembleMatterExport(db, matterId, { keys });
    exportResult = persistMatterExport(db, matterId, assembled);
  }
  return { matter, export: exportResult };
}
