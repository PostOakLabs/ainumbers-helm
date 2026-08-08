import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, createHash } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-matter-test-"));
process.env.HELM_HOME = TMP;

const HERE = dirname(fileURLToPath(import.meta.url));

const { openJournal } = await import("./journal.mjs");
const { executeRun } = await import("./run.mjs");
const { runAttestedArtifact } = await import("./attested-artifact-runner.mjs");
const { initHaTables } = await import("./ha-store.mjs");
const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { verifyEnvelope } = await import("./envelope.mjs");
const {
  generateUlid,
  computeManifestDigest,
  createMatter,
  getMatter,
  listMatters,
  updateMatter,
  deleteMatter,
  unresolvedBindings,
  registerEvidenceBundle,
  assembleMatterExport,
  closeMatter,
  getMatterExport,
} = await import("./matter-store.mjs");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);

function dbAt(name) {
  return openJournal(join(TMP, name));
}

function randomSha256Ref() {
  return `sha256:${randomBytes(32).toString("hex")}`;
}

function entityInput(overrides = {}) {
  return {
    entity: { id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" },
    ...overrides,
  };
}

// Bypasses ha-store's full signature-verification write path (submitHaRecord
// needs a real did:key signature, which is out of scope for a binding-
// resolution test) — inserts directly into the table ha-store.mjs itself
// owns, at the exact shape recordsForSubject/appendHaRecord produce, so this
// only tests OUR resolver's read, not ha-store's write.
function insertHaRecordDirect(db, { recordId, subjectHash }) {
  initHaTables(db);
  db.prepare(
    `INSERT INTO ha_records (record_id, subject_hash, record_type, role, identity_id, record_json, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(recordId, subjectHash, "approval", "reviewer", "did:key:test", JSON.stringify({ subject_hash: subjectHash }), new Date().toISOString());
}

async function completeSimpleRun(db, runId) {
  return executeRun(db, {
    runId,
    manifest: {
      manifest_version: "1",
      workflow_id: "wf-matter-test",
      trigger: { type: "manual" },
      nodes: [],
      connectors: [],
      gates: [],
      actions: [],
    },
    stepRunner: async (step) => ({ ok: true, step_id: step.step_id }),
  });
}

async function completeAttestedArtifactRun(db, runId, artifactId = "aa-1") {
  const manifest = {
    manifest_version: "1",
    workflow_id: "wf-matter-attested-test",
    trigger: { type: "manual" },
    nodes: [],
    connectors: [],
    gates: [],
    actions: [],
    attested_artifacts: [
      {
        artifact_id: artifactId,
        tool_ref: { manifest_digest: `sha256:${"1".repeat(64)}` },
        inputs_digest: `sha256:${"2".repeat(64)}`,
        artifact: { content_digest: `sha256:${"3".repeat(64)}` },
      },
    ],
  };
  await executeRun(db, {
    runId,
    manifest,
    stepRunner: async (step) => (step.kind === "attested_artifacts" ? runAttestedArtifact(step) : { ok: true }),
  });
  const row = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").get(runId, `attested_artifacts:${artifactId}`);
  // stored bare-hex (attested-artifact-runner.mjs convention, matching
  // ha-gate.mjs's own subjectHashFor) — prefix here, at the boundary where
  // this test treats it as a subject_hash-shaped value.
  return `sha256:${JSON.parse(row.output_json).artifact.execution_hash}`;
}

test("matter-store: generateUlid matches the schema's Crockford base32 pattern", () => {
  const id = generateUlid();
  assert.match(id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.notEqual(id, generateUlid()); // two calls never collide
});

test("matter-store: computeManifestDigest matches the HELM-MATTER-S1 golden fixture", () => {
  const golden = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "matter-manifest", "golden.json"), "utf8"));
  assert.equal(computeManifestDigest(golden), golden.manifest_digest);
});

test("matter-store: computeManifestDigest diverges from the tampered-digest-mismatch fixture's stale digest", () => {
  const tampered = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "matter-manifest", "tampered-digest-mismatch.json"), "utf8"));
  assert.notEqual(computeManifestDigest(tampered), tampered.manifest_digest);
});

test("matter-store: create — minimal matter, no bindings, defaults applied and shape valid", () => {
  const db = dbAt("create-minimal.db");
  const matter = createMatter(db, entityInput());
  assert.match(matter.matter_id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
  assert.equal(matter.status, "intake");
  assert.deepEqual(matter.parties, []);
  assert.deepEqual(matter.deadlines, []);
  assert.deepEqual(matter.bindings, []);
  assert.equal(matter.manifest_digest, computeManifestDigest(matter));
  assert.equal(matter.created_at, matter.updated_at);
  db.close();
});

test("matter-store: create refuses an unresolved run binding", () => {
  const db = dbAt("create-bad-run.db");
  assert.throws(
    () => createMatter(db, entityInput({ bindings: [{ subject_hash: randomSha256Ref(), subject_kind: "run" }] })),
    /does not resolve/
  );
  db.close();
});

test("matter-store: create accepts a run binding once the run has actually completed", async () => {
  const db = dbAt("create-good-run.db");
  const result = await completeSimpleRun(db, "run-matter-1");
  assert.equal(result.state, "completed");
  const matter = createMatter(db, entityInput({ bindings: [{ subject_hash: result.executionHash, subject_kind: "run" }] }));
  assert.equal(matter.bindings[0].subject_hash, result.executionHash);
  db.close();
});

test("matter-store: approval_record binding resolves against ha_records, rejects an unknown record_id", () => {
  const db = dbAt("create-ha.db");
  const recordId = `sha256:${createHash("sha256").update("fixture-record").digest("hex")}`;
  insertHaRecordDirect(db, { recordId, subjectHash: randomSha256Ref() });

  const matter = createMatter(db, entityInput({ bindings: [{ subject_hash: recordId, subject_kind: "approval_record" }] }));
  assert.equal(matter.bindings[0].subject_hash, recordId);

  assert.throws(
    () => createMatter(db, entityInput({ bindings: [{ subject_hash: randomSha256Ref(), subject_kind: "approval_record" }] })),
    /does not resolve/
  );
  db.close();
});

test("matter-store: attested_artifact binding resolves against a memoized attested-artifacts step", async () => {
  const db = dbAt("create-attested.db");
  const executionHash = await completeAttestedArtifactRun(db, "run-matter-attested-1");
  assert.match(executionHash, /^sha256:[0-9a-f]{64}$/);

  const matter = createMatter(db, entityInput({ bindings: [{ subject_hash: executionHash, subject_kind: "attested_artifact" }] }));
  assert.equal(matter.bindings[0].subject_hash, executionHash);

  assert.throws(
    () => createMatter(db, entityInput({ bindings: [{ subject_hash: randomSha256Ref(), subject_kind: "attested_artifact" }] })),
    /does not resolve/
  );
  db.close();
});

test("matter-store: evidence_bundle binding resolves only after registerEvidenceBundle", () => {
  const db = dbAt("create-bundle.db");
  const digest = randomSha256Ref();

  assert.throws(
    () => createMatter(db, entityInput({ bindings: [{ subject_hash: digest, subject_kind: "evidence_bundle" }] })),
    /does not resolve/
  );

  registerEvidenceBundle(db, digest, { runId: "run-x" });
  const matter = createMatter(db, entityInput({ bindings: [{ subject_hash: digest, subject_kind: "evidence_bundle" }] }));
  assert.equal(matter.bindings[0].subject_hash, digest);

  // idempotent — re-registering the same digest is a no-op, not an error
  assert.doesNotThrow(() => registerEvidenceBundle(db, digest, { runId: "run-x" }));
  db.close();
});

test("matter-store: external_reference binding is never checked against local storage", () => {
  const db = dbAt("create-external.db");
  const neverResolvable = randomSha256Ref();
  const matter = createMatter(
    db,
    entityInput({ bindings: [{ subject_hash: neverResolvable, subject_kind: "external_reference", note: "received PDF" }] })
  );
  assert.equal(matter.bindings[0].subject_hash, neverResolvable);
  assert.deepEqual(unresolvedBindings(db, matter.bindings), []);
  db.close();
});

test("matter-store: create refuses a manifest that fails §2 schema shape (unknown subject_kind)", () => {
  const db = dbAt("create-bad-shape.db");
  assert.throws(
    () => createMatter(db, entityInput({ bindings: [{ subject_hash: randomSha256Ref(), subject_kind: "not_a_real_kind" }] })),
    /refused create/
  );
  db.close();
});

test("matter-store: get/list/update/delete round trip", () => {
  const db = dbAt("crud.db");
  const created = createMatter(db, entityInput({ status: "working", narrative: "initial" }));

  const fetched = getMatter(db, created.matter_id);
  assert.deepEqual(fetched, created);

  const listed = listMatters(db);
  assert.equal(listed.length, 1);
  assert.equal(listed[0].matter_id, created.matter_id);

  const filtered = listMatters(db, { status: "working" });
  assert.equal(filtered.length, 1);
  assert.equal(listMatters(db, { status: "closed" }).length, 0);

  const updated = updateMatter(db, created.matter_id, { status: "closed", narrative: "wrapped up" });
  assert.equal(updated.status, "closed");
  assert.equal(updated.narrative, "wrapped up");
  assert.equal(updated.matter_id, created.matter_id);
  assert.equal(updated.created_at, created.created_at);
  assert.notEqual(updated.manifest_digest, created.manifest_digest);
  assert.equal(updated.manifest_digest, computeManifestDigest(updated));

  assert.equal(deleteMatter(db, created.matter_id), true);
  assert.equal(getMatter(db, created.matter_id), null);
  assert.equal(deleteMatter(db, created.matter_id), false);
  db.close();
});

test("matter-store: update on an unknown matter_id throws", () => {
  const db = dbAt("update-unknown.db");
  assert.throws(() => updateMatter(db, "01UNKNOWNMATTERIDXXXXXXXX", { status: "closed" }), /unknown matter_id/);
  db.close();
});

test("matter-store: update refuses to remove or un-done a done:true deadline (append-only)", () => {
  const db = dbAt("update-append-only.db");
  const created = createMatter(
    db,
    entityInput({
      deadlines: [{ date: "2026-08-01", action: "Produce evidence", type: "document-production", source: "test", done: true, done_at: "2026-07-30T00:00:00Z" }],
    })
  );

  assert.throws(() => updateMatter(db, created.matter_id, { deadlines: [] }), /append-only/);

  assert.throws(
    () =>
      updateMatter(db, created.matter_id, {
        deadlines: [{ date: "2026-08-01", action: "Produce evidence", type: "document-production", source: "test", done: false }],
      }),
    /append-only/
  );

  // adding a NEW deadline alongside the untouched done:true one is legal
  const updated = updateMatter(db, created.matter_id, {
    deadlines: [
      { date: "2026-08-01", action: "Produce evidence", type: "document-production", source: "test", done: true, done_at: "2026-07-30T00:00:00Z" },
      { date: "2026-09-15", action: "Respond to request #2", type: "regulatory-response", source: "test", done: false },
    ],
  });
  assert.equal(updated.deadlines.length, 2);
  db.close();
});

// ---------------------------------------------------------------------------
// HELM-MATTER-H2: §5 closeout export.

test("closeMatter: transitioning to closed with keys emits a signed export covering every resolving binding kind", async () => {
  const db = dbAt("close-full.db");
  const runResult = await completeSimpleRun(db, "run-close-1");
  const attestedHash = await completeAttestedArtifactRun(db, "run-close-attested-1", "aa-close-1");
  const recordId = `sha256:${createHash("sha256").update("close-fixture-record").digest("hex")}`;
  const haSubjectHash = randomSha256Ref();
  insertHaRecordDirect(db, { recordId, subjectHash: haSubjectHash });
  const bundleDigest = randomSha256Ref();
  registerEvidenceBundle(db, bundleDigest, { runId: runResult.runId });
  const externalHash = randomSha256Ref();

  const matter = createMatter(db, entityInput({
    status: "working",
    bindings: [
      { subject_hash: runResult.executionHash, subject_kind: "run" },
      { subject_hash: attestedHash, subject_kind: "attested_artifact" },
      { subject_hash: recordId, subject_kind: "approval_record" },
      { subject_hash: bundleDigest, subject_kind: "evidence_bundle" },
      { subject_hash: externalHash, subject_kind: "external_reference", note: "received PDF" },
    ],
  }));

  const { matter: closed, export: exported } = closeMatter(db, matter.matter_id, { status: "closed" }, keys);
  assert.equal(closed.status, "closed");
  assert.ok(exported);
  assert.match(exported.envelope_digest, /^sha256:[0-9a-f]{64}$/);

  // The envelope is a REAL, independently-verifiable DSSE signature — not
  // merely a digest label — over the exact predicate this test inspects
  // below (verifyEnvelope re-derives `statement` from the envelope itself).
  const verified = verifyEnvelope(exported.envelope, publicKeys);
  assert.equal(verified.valid, true);
  assert.equal(verified.statement.predicate.matter_id, matter.matter_id);
  assert.equal(verified.statement.predicate.matter_manifest_digest, closed.manifest_digest);

  const byHash = Object.fromEntries(exported.predicate.bindings_export.map((b) => [b.subject_hash, b]));

  assert.equal(byHash[runResult.executionHash].exported, true);
  assert.equal(byHash[runResult.executionHash].artifact.trust_label, "hash_verified");
  assert.equal(byHash[runResult.executionHash].artifact.run_id, runResult.runId);

  assert.equal(byHash[attestedHash].exported, true);
  assert.equal(byHash[attestedHash].artifact.artifact_id, "aa-close-1");

  assert.equal(byHash[recordId].exported, true);
  assert.equal(byHash[recordId].artifact.subject_hash, haSubjectHash);

  assert.equal(byHash[bundleDigest].exported, true);
  assert.equal(byHash[bundleDigest].artifact.run_id, runResult.runId);
  assert.equal(byHash[bundleDigest].artifact.run_evidence.run_id, runResult.runId);

  assert.equal(byHash[externalHash].exported, false);
  assert.match(byHash[externalHash].reason, /external_reference/);
  assert.equal(byHash[externalHash].note, "received PDF");

  // Persisted — a fresh read returns the SAME export, not a recomputation.
  const reread = getMatterExport(db, matter.matter_id);
  assert.equal(reread.envelope_digest, exported.envelope_digest);
  assert.deepEqual(reread.envelope, exported.envelope);
  db.close();
});

test("closeMatter: without keys, the status change applies but no export is emitted or persisted", () => {
  const db = dbAt("close-no-keys.db");
  const matter = createMatter(db, entityInput({ status: "working" }));

  const { matter: closed, export: exported } = closeMatter(db, matter.matter_id, { status: "closed" }, undefined);
  assert.equal(closed.status, "closed");
  assert.equal(exported, undefined);
  assert.equal(getMatterExport(db, matter.matter_id), null);
  db.close();
});

test("closeMatter: an already-closed matter never re-emits on a later edit (signed exactly once per closure)", () => {
  const db = dbAt("close-once.db");
  const matter = createMatter(db, entityInput({ status: "working" }));

  const first = closeMatter(db, matter.matter_id, { status: "closed" }, keys);
  assert.ok(first.export);

  const second = closeMatter(db, matter.matter_id, { narrative: "post-closure note" }, keys);
  assert.equal(second.matter.status, "closed");
  assert.equal(second.export, undefined);

  // The persisted export is untouched — same digest as the original closure.
  const stillOriginal = getMatterExport(db, matter.matter_id);
  assert.equal(stillOriginal.envelope_digest, first.export.envelope_digest);
  db.close();
});

test("assembleMatterExport: refuses on a matter that is not closed", () => {
  const db = dbAt("assemble-not-closed.db");
  const matter = createMatter(db, entityInput({ status: "working" }));
  assert.throws(() => assembleMatterExport(db, matter.matter_id, { keys }), /is not closed/);
  db.close();
});

test("assembleMatterExport: refuses without signing keys", () => {
  const db = dbAt("assemble-no-keys.db");
  const matter = createMatter(db, entityInput({ status: "closed" }));
  assert.throws(() => assembleMatterExport(db, matter.matter_id), /requires signing keys/);
  db.close();
});

test("assembleMatterExport: refuses on an unknown matter_id", () => {
  const db = dbAt("assemble-unknown.db");
  assert.throws(() => assembleMatterExport(db, "01UNKNOWNMATTERIDXXXXXXXX", { keys }), /unknown matter_id/);
  db.close();
});

test("getMatterExport: returns null for a matter that was never closed", () => {
  const db = dbAt("export-null.db");
  const matter = createMatter(db, entityInput());
  assert.equal(getMatterExport(db, matter.matter_id), null);
  db.close();
});
