import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-ha-store-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { appendHaRecord, recordsForSubject, validateHaRecordShape, getOrInitSlot, addCountersignature, getSlot } = await import("./ha-store.mjs");
const { sign, rawPubkeyToDidKey } = await import("./vendored/ocg/kernels/_proof.mjs");

const SUBJECT = "sha256:" + "1".repeat(64);

async function signedApproval(overrides = {}) {
  const keyPair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const id = await rawPubkeyToDidKey(keyPair.publicKey);
  const unsigned = {
    record_type: "approval",
    role: "approver",
    subject_hash: SUBJECT,
    identity: { id },
    decision: "approve",
    timestamp: "2026-07-24T12:00:00Z",
    ...overrides,
  };
  const signed = await sign(unsigned, { verificationMethod: `${id}#key-1`, created: "2026-07-24T12:00:00Z", privateKey: keyPair.privateKey });
  return { signed, id };
}

function dbAt(name) {
  return openJournal(join(TMP, name));
}

test("validateHaRecordShape: accepts a well-formed signed approval", async () => {
  const { signed } = await signedApproval();
  assert.deepEqual(validateHaRecordShape(signed).errors, []);
});

test("validateHaRecordShape: refuses a record missing subject_hash", async () => {
  const { signed } = await signedApproval();
  delete signed.subject_hash;
  const result = validateHaRecordShape(signed);
  assert.equal(result.ok, false);
});

test("validateHaRecordShape: refuses an unsigned record (no conformant proof)", () => {
  const result = validateHaRecordShape({ record_type: "approval", role: "approver", subject_hash: SUBJECT, identity: { id: "did:key:zNoSig" } });
  assert.equal(result.ok, false);
});

test("appendHaRecord + recordsForSubject: stores and retrieves by subject_hash", async () => {
  const db = dbAt("append.db");
  const { signed } = await signedApproval();
  appendHaRecord(db, signed);
  const records = recordsForSubject(db, SUBJECT);
  assert.equal(records.length, 1);
  assert.equal(records[0].identity.id, signed.identity.id);
  db.close();
});

test("appendHaRecord: resubmitting the identical record is idempotent, not a duplicate", async () => {
  const db = dbAt("idempotent.db");
  const { signed } = await signedApproval();
  appendHaRecord(db, signed);
  appendHaRecord(db, signed);
  assert.equal(recordsForSubject(db, SUBJECT).length, 1);
  db.close();
});

test("appendHaRecord: refuses a shape-invalid record rather than storing it half-valid", () => {
  const db = dbAt("refuse.db");
  assert.throws(() => appendHaRecord(db, { record_type: "approval" }), /ha-store: refused record/);
  db.close();
});

test("countersignature slot: getOrInitSlot creates once, addCountersignature accumulates distinct entries", async () => {
  const db = dbAt("slot.db");
  const slot0 = getOrInitSlot(db, SUBJECT, { keyid: "maker", sig: "x", alg: "Ed25519" });
  assert.equal(slot0.countersignatures.length, 0);

  const c1 = { role: "checker", identity: { id: "did:key:zA" }, signature: { keyid: "did:key:zA", sig: "s1", alg: "Ed25519" }, signed_at: "2026-07-24T12:00:00Z", replay_verified: true };
  const c2 = { role: "checker", identity: { id: "did:key:zB" }, signature: { keyid: "did:key:zB", sig: "s2", alg: "Ed25519" }, signed_at: "2026-07-24T12:05:00Z", replay_verified: true };
  addCountersignature(db, SUBJECT, c1);
  const slot = addCountersignature(db, SUBJECT, c2);

  assert.equal(slot.countersignatures.length, 2);
  assert.equal(getSlot(db, SUBJECT).countersignatures.length, 2);
  db.close();
});
