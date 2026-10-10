// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Pin test for helm record canonicalization v1 (HELM-CANON-SPLIT-1).
//
// The expected strings below were computed by the PRE-911cfe38 code (the
// vendored cgCanon at site pin 0914b432, composed with JSON.stringify) — the
// exact serializer that produced every stored helm record digest to date.
// They pin the two v1 behaviors a well-meaning later "cleanup" to jcsStringify
// would silently break:
//   - array-index member names stay in JavaScript enumeration order
//     (numeric-first), NOT RFC 8785 UTF-16 order;
//   - a literal "__proto__" member is dropped from the preimage (prototype
//     assignment with a plain {} accumulator), never preserved.
// If any of these assertions goes red, a record digest is about to move:
// STOP — do not "fix" this test, and do not upgrade the serializer.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash as sha } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { recordCanonV1 } from "./record-canon-v1.mjs";
import { openJournal, replayVerify } from "./journal.mjs";
import { initHaTables, getRecordById, getSlot } from "./ha-store.mjs";
import { verifyHaRecordSignature, verifyBundleDigestSignature } from "./ha-gate.mjs";
import { runAttestedArtifact } from "./attested-artifact-runner.mjs";
import { loadContract } from "./connector.mjs";
import { jcsStringify } from "./vendored/ocg/kernels/_hash.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "fixtures", "canon-v1");

// Rebuilds the old-pin journal in memory from the committed row bytes (the
// fixture is JSON, not a .db file — repo .gitignore excludes *.db and the
// digest checks below are the point, not the SQLite container).
function loadFixture() {
  return JSON.parse(readFileSync(join(FIXTURES, "journal-fixture.json"), "utf8"));
}

function rebuildDb(fixture) {
  const db = openJournal(":memory:");
  initHaTables(db);
  for (const e of fixture.entries) {
    db.prepare(
      "INSERT INTO journal (seq, stream_id, kind, run_id, entry_json, entry_digest, rh, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(e.seq, e.stream_id, e.kind, e.run_id, e.entry_json, e.entry_digest, e.rh, e.created_at);
  }
  for (const s of fixture.stream_state) {
    db.prepare("INSERT INTO stream_state (stream_id, last_seq, last_rh) VALUES (?, ?, ?)").run(s.stream_id, s.last_seq, s.last_rh);
  }
  for (const r of fixture.ha_records) {
    db.prepare(
      "INSERT INTO ha_records (record_id, subject_hash, record_type, role, identity_id, record_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).run(r.record_id, r.subject_hash, r.record_type, r.role, r.identity_id, r.record_json, r.created_at);
  }
  for (const s of fixture.ha_countersignature_slots) {
    db.prepare("INSERT INTO ha_countersignature_slots (subject_hash, slot_json, updated_at) VALUES (?, ?, ?)").run(s.subject_hash, s.slot_json, s.updated_at);
  }
  return db;
}

function entryDigestHex(entryJson) {
  return sha("sha256").update(recordCanonV1(JSON.parse(entryJson)), "utf8").digest("hex");
}

test("record-canon-v1: exact v1 bytes for the pin vectors (pre-911cfe38 code, computed at the old pin)", () => {
  // Vector A — array-index names: v1 keeps JS numeric-first enumeration order.
  // RFC 8785 (jcsStringify) would emit {"10":2,"9":1}; v1 deliberately does not.
  assert.equal(recordCanonV1({ 9: 1, 10: 2 }), '{"9":1,"10":2}');
  // Vector B — mixed integer/non-integer names: integer-like keys first.
  assert.equal(recordCanonV1({ 1: 1, "!": 2 }), '{"1":1,"!":2}');
  // Vector C — astral-plane key (UTF-16 surrogate pair, code unit 0xD83D >
  // "a" 0x61, so it sorts last — same relative order both serializers).
  assert.equal(recordCanonV1({ a: 2, "\u{1F600}": 1 }), '{"a":2,"😀":1}');
  // Vector D — literal "__proto__" member: frozen v1 DROPS it from the
  // preimage (prototype assignment on the {} accumulator). The new vendored
  // canonicalizer keeps it — that difference is exactly why this module is
  // frozen and self-contained.
  assert.equal(recordCanonV1(JSON.parse('{"__proto__":{"x":1},"a":2}')), '{"a":2}');
  // Combined vector — all three behaviors in one preimage.
  assert.equal(
    recordCanonV1(JSON.parse('{"9":1,"10":2,"__proto__":{"z":9},"\u{1F600}":3}')),
    '{"9":1,"10":2,"\u{1F600}":3}'
  );
});

// Step-8 fixture proof: a journal and a countersigned HA record CREATED at
// the old pin (vendored 0914b432, pre-freeze helpers) still verify after the
// v1 freeze and the re-vendor. These fixtures are committed bytes — never
// regenerate them against changed code to make a red go green (STOP (d)).
test("record-canon-v1: old-pin fixture entry digests recompute byte-identically (digests unchanged across the re-vendor)", () => {
  const fixture = loadFixture();
  assert.equal(fixture.pinned_at_site_sha, "0914b432182a6ea883eb250e4c4523043113739e");
  // The canon-sensitive entry carries array-index keys ("9"/"10"), an
  // astral-plane key and a literal "__proto__" member — the exact cases
  // where the vendored canonicalizer changed.
  const canonEntry = fixture.entries.find((e) => e.stream_id === "fixture:canon");
  assert.ok(canonEntry, "canon-sensitive fixture entry missing"); // recorded digests are the witness
  for (const e of fixture.entries) {
    assert.equal(
      entryDigestHex(e.entry_json),
      e.entry_digest,
      `entry_digest for ${e.stream_id} seq ${e.seq} moved — a stored helm record digest would change (STOP (b))`
    );
  }
  // And the full hash chain over those recorded digests still replays clean.
  const db = rebuildDb(fixture);
  try {
    assert.deepEqual(replayVerify(db), { ok: true, brokenAt: null });
  } finally {
    db.close();
  }
});

test("record-canon-v1: old-pin countersigned HA record still verifies cryptographically", async () => {
  const { record, recordId } = JSON.parse(readFileSync(join(FIXTURES, "ha-record.json"), "utf8"));
  assert.equal(recordId, "sha256:f0bab97a12682337a02f4004348a6053829cb0d6563c65b86cbd9d58f978c905");
  assert.equal(await verifyHaRecordSignature(record), true);

  const { subjectHash, slot } = JSON.parse(readFileSync(join(FIXTURES, "ha-slot.json"), "utf8"));
  const db = rebuildDb(loadFixture());
  try {
    // The stored slot row (rebuilt from the committed fixture bytes) must
    // match the committed copy and verify against the recorded digests.
    assert.deepEqual(getSlot(db, subjectHash), slot);
    assert.equal(await verifyBundleDigestSignature(subjectHash, slot.maker_signature), true);
    assert.equal(await verifyBundleDigestSignature(subjectHash, slot.countersignatures[0].signature), true);
    // And the record's own id (its v1 JCS digest) is still reproducible.
    assert.deepEqual(getRecordById(db, recordId), record);
  } finally {
    db.close();
  }
});

// Step-6 verify paths (ruling 2026-10-01): artifacts from the site/Worker are
// hashed jcs-first with a DISTINCT legacy verdict on divergence, never a plain
// unqualified pass.
const sha256hex = (s) => sha("sha256").update(s, "utf8").digest("hex");
const attestedStep = (toolRefExtra) => ({
  kind: "attested_artifacts",
  item: {
    artifact_id: "a1",
    tool_ref: { manifest_digest: "sha256:" + "1".repeat(64), ...toolRefExtra },
    inputs_digest: "sha256:" + "2".repeat(64),
    artifact: { content_type: "application/json", content_digest: "sha256:" + "3".repeat(64) },
  },
});

test("record-canon-v1: attested-artifact verify path reports rfc8785 for ordinary objects", async () => {
  const out = await runAttestedArtifact(attestedStep({}));
  assert.equal(out.canonicalization, "rfc8785");
  // The digest is the RFC 8785 preimage (site/Worker parity).
  assert.equal(
    out.artifact.execution_hash,
    sha256hex(jcsStringify({ tool_ref: attestedStep({}).item.tool_ref, inputs_digest: attestedStep({}).item.inputs_digest, artifact: attestedStep({}).item.artifact }))
  );
});

test("record-canon-v1: attested-artifact verify path reports the DISTINCT legacy verdict when v1 bytes differ", async () => {
  // An array-index member name inside the hashed object is exactly the case
  // where jcsStringify and the frozen v1 serializer disagree.
  const out = await runAttestedArtifact(attestedStep({ "source_index": { 9: 1, 10: 2 } }));
  assert.equal(out.canonicalization, "legacy-v1-divergent");
  assert.equal(out.trust_label, "hash_verified");
  assert.equal(
    out.artifact.execution_hash,
    sha256hex(jcsStringify({ tool_ref: { manifest_digest: "sha256:" + "1".repeat(64), source_index: { 9: 1, 10: 2 } }, inputs_digest: "sha256:" + "2".repeat(64), artifact: { content_type: "application/json", content_digest: "sha256:" + "3".repeat(64) } }))
  );
});

test("record-canon-v1: connector contract verify path classifies a real contract (rfc8785; digest reproducible)", () => {
  // Real contract shipped with helm — plain I-JSON, no divergent members.
  const { contractDigest, canonicalization } = loadContract(join(import.meta.dirname, "connectors", "google-drive-fetch.contract.json"));
  assert.equal(canonicalization, "rfc8785");
  assert.match(contractDigest, /^sha256:[0-9a-f]{64}$/);
});
