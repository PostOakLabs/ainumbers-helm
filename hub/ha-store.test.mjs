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

  const c1 = { role: "checker", identity: { id: "did:key:zA" }, signature: { keyid: "did:key:zA", sig: "s1", alg: "Ed25519" }, signed_at: "2026-07-24T12:00:00Z", replay_verified: true, attester_kind: "human" };
  const c2 = { role: "checker", identity: { id: "did:key:zB" }, signature: { keyid: "did:key:zB", sig: "s2", alg: "Ed25519" }, signed_at: "2026-07-24T12:05:00Z", replay_verified: true, attester_kind: "human" };
  addCountersignature(db, SUBJECT, c1);
  const slot = addCountersignature(db, SUBJECT, c2);

  assert.equal(slot.countersignatures.length, 2);
  assert.equal(getSlot(db, SUBJECT).countersignatures.length, 2);
  db.close();
});

test("addCountersignature: refuses when the slot has no maker_signature.keyid (MC-1.1, RED without the fix)", async () => {
  const db = dbAt("mc11-no-maker.db");
  getOrInitSlot(db, SUBJECT, null);
  const c = { role: "checker", identity: { id: "did:key:zChecker" }, signature: { keyid: "did:key:zChecker", sig: "s1", alg: "Ed25519" }, signed_at: "2026-07-24T12:00:00Z" };
  assert.throws(() => addCountersignature(db, SUBJECT, c), /MC-1\.1: absence of a maker is a refusal/);
  db.close();
});

test("addCountersignature: refuses a countersignature whose identity equals the maker's (MC-1, RED without the fix)", async () => {
  const db = dbAt("mc1-same-identity.db");
  getOrInitSlot(db, SUBJECT, { keyid: "did:key:zMaker", sig: "x", alg: "Ed25519" });
  const c = { role: "checker", identity: { id: "did:key:zMaker" }, signature: { keyid: "did:key:zMaker", sig: "s1", alg: "Ed25519" }, signed_at: "2026-07-24T12:00:00Z" };
  assert.throws(() => addCountersignature(db, SUBJECT, c), /MC-1: same-identity countersignature forbidden/);
  db.close();
});

test("addCountersignature: a checker distinct from the maker is accepted", async () => {
  const db = dbAt("mc1-distinct.db");
  getOrInitSlot(db, SUBJECT, { keyid: "did:key:zMaker", sig: "x", alg: "Ed25519" });
  const c = { role: "checker", identity: { id: "did:key:zChecker" }, signature: { keyid: "did:key:zChecker", sig: "s1", alg: "Ed25519" }, signed_at: "2026-07-24T12:00:00Z", attester_kind: "human" };
  const slot = addCountersignature(db, SUBJECT, c);
  assert.equal(slot.countersignatures.length, 1);
  db.close();
});

test("addCountersignature: refuses a countersignature with no explicit attester_kind (MC-2.1)", async () => {
  const db = dbAt("mc21-no-kind.db");
  getOrInitSlot(db, SUBJECT, { keyid: "did:key:zMaker", sig: "x", alg: "Ed25519" });
  const c = { role: "checker", identity: { id: "did:key:zChecker" }, signature: { keyid: "did:key:zChecker", sig: "s1", alg: "Ed25519" }, signed_at: "2026-07-24T12:00:00Z" };
  assert.throws(() => addCountersignature(db, SUBJECT, c), /MC-2\.1/);
  db.close();
});

test("setMakerSignature: an explicit maker act establishes the slot's maker_signature (MC-1.2)", async () => {
  const db = dbAt("mc12-maker.db");
  const { setMakerSignature } = await import("./ha-store.mjs");
  const slot = setMakerSignature(db, SUBJECT, { keyid: "did:key:zMaker", sig: "m1", alg: "EdDSA", attester_kind: "human" });
  assert.equal(slot.maker_signature.keyid, "did:key:zMaker");
  assert.equal(getSlot(db, SUBJECT).maker_signature.keyid, "did:key:zMaker");
  db.close();
});

test("setMakerSignature: refuses to swap the maker under a different keyid", async () => {
  const db = dbAt("mc12-noswap.db");
  const { setMakerSignature } = await import("./ha-store.mjs");
  setMakerSignature(db, SUBJECT, { keyid: "did:key:zMaker1", sig: "m1", alg: "EdDSA", attester_kind: "human" });
  assert.throws(
    () => setMakerSignature(db, SUBJECT, { keyid: "did:key:zMaker2", sig: "m2", alg: "EdDSA", attester_kind: "human" }),
    /never silently swapped/
  );
  db.close();
});

test("setMakerSignature: re-submitting the SAME maker keyid is idempotent, not a swap", async () => {
  const db = dbAt("mc12-resubmit.db");
  const { setMakerSignature } = await import("./ha-store.mjs");
  setMakerSignature(db, SUBJECT, { keyid: "did:key:zMaker", sig: "m1", alg: "EdDSA", attester_kind: "human" });
  const slot = setMakerSignature(db, SUBJECT, { keyid: "did:key:zMaker", sig: "m1", alg: "EdDSA", attester_kind: "human" });
  assert.equal(slot.maker_signature.keyid, "did:key:zMaker");
  db.close();
});

test("distinctHumanCheckerIds: MC-1.3 collapses repeats, MC-2.2 excludes automated", async () => {
  const { distinctHumanCheckerIds } = await import("./ha-store.mjs");
  const cs = [
    { identity: { id: "did:key:zA" }, attester_kind: "human", signed_at: "t1" },
    { identity: { id: "did:key:zA" }, attester_kind: "human", signed_at: "t2" }, // same human, different instant
    { identity: { id: "did:key:zB" }, attester_kind: "automated", signed_at: "t3" }, // daemon — must not count
  ];
  assert.deepEqual([...distinctHumanCheckerIds(cs)], ["did:key:zA"]);
});

test("pinSlotSatisfaction: pins threshold+as_of once distinct human checkers meet it, and never counts automated (MC-2.2, E-6, E-7)", async () => {
  const db = dbAt("pin-satisfaction.db");
  const { setMakerSignature, pinSlotSatisfaction } = await import("./ha-store.mjs");
  setMakerSignature(db, SUBJECT, { keyid: "did:key:zMaker", sig: "m1", alg: "EdDSA", attester_kind: "human" });
  addCountersignature(db, SUBJECT, { role: "checker", identity: { id: "did:key:zAuto" }, signature: { keyid: "did:key:zAuto", sig: "s0", alg: "EdDSA" }, signed_at: "t0", attester_kind: "automated" });

  const notYet = pinSlotSatisfaction(db, SUBJECT, { requiredThreshold: 1, nowISO: "2026-08-17T00:00:00Z" });
  assert.equal(notYet.threshold, undefined, "an automated-only slot must not pin as satisfied");

  addCountersignature(db, SUBJECT, { role: "checker", identity: { id: "did:key:zHuman" }, signature: { keyid: "did:key:zHuman", sig: "s1", alg: "EdDSA" }, signed_at: "t1", attester_kind: "human" });
  const pinned = pinSlotSatisfaction(db, SUBJECT, { requiredThreshold: 1, nowISO: "2026-08-17T01:00:00Z" });
  assert.equal(pinned.threshold, 1);
  assert.equal(pinned.as_of, "2026-08-17T01:00:00Z");

  // Immutable once pinned — a later call with a different threshold/clock does not move it.
  const stillPinned = pinSlotSatisfaction(db, SUBJECT, { requiredThreshold: 5, nowISO: "2026-08-18T00:00:00Z" });
  assert.equal(stillPinned.threshold, 1);
  assert.equal(stillPinned.as_of, "2026-08-17T01:00:00Z");
  db.close();
});
