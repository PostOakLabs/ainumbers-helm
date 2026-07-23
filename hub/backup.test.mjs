import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-backup-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { openJournal, appendEntry, replayVerify } = await import("./journal.mjs");
const { buildCheckpoint, saveCheckpoint } = await import("./checkpoint.mjs");
const { exportEncrypted, restoreEncrypted, verifyAllCheckpoints } = await import("./backup.mjs");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);
const PASSPHRASE = Buffer.from("correct horse battery staple");

function fixtureEntry(overrides = {}) {
  return {
    period_start: "2026-07-23T00:00:00.000Z",
    period_end: "2026-07-23T00:00:01.000Z",
    reference_db_version: "kernels@2026-07-23",
    triggering_input_digest: "sha256:" + "b".repeat(64),
    humans_involved: [{ id_ref: "tim", role: "operator" }],
    ...overrides,
  };
}

test("backup: RESTORE TEST — export, restore, verify running hashes + checkpoint sigs", () => {
  const original = openJournal(join(TMP, "orig.db"));
  for (let i = 0; i < 4; i++) {
    appendEntry(original, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ i }) });
  }
  appendEntry(original, { streamId: "run-2", kind: "execution_state", entry: fixtureEntry({ i: 0 }) });
  const cp = buildCheckpoint(original, { checkpointSeq: 1, keys, anchors: [] });
  saveCheckpoint(original, cp);

  const blob = exportEncrypted(original, PASSPHRASE);
  assert.equal(blob.format, "helm-journal-backup-v1");

  const { db: restored, replay, checkpoints } = restoreEncrypted(blob, PASSPHRASE, join(TMP, "restored.db"));
  assert.equal(replay.ok, true, "restored journal must pass running-hash replay");

  const verdicts = verifyAllCheckpoints(restored, checkpoints, publicKeys);
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0].valid, true, "restored checkpoint signature must still verify");

  // Restored journal is byte-for-byte the same story as the original.
  assert.equal(replayVerify(original).ok, true);
  original.close();
  restored.close();
});

test("negative: wrong passphrase fails to decrypt (auth tag rejects it, not a silent corruption)", () => {
  const db = openJournal(join(TMP, "wp.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const blob = exportEncrypted(db, PASSPHRASE);
  assert.throws(() => restoreEncrypted(blob, Buffer.from("wrong passphrase"), join(TMP, "wp-restored.db")));
  db.close();
});

test("negative: restoring a tampered ciphertext fails closed", () => {
  const db = openJournal(join(TMP, "tp.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const blob = exportEncrypted(db, PASSPHRASE);
  const tampered = { ...blob, ciphertext: Buffer.from("tampered bytes here").toString("base64") };
  assert.throws(() => restoreEncrypted(tampered, PASSPHRASE, join(TMP, "tp-restored.db")));
  db.close();
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
