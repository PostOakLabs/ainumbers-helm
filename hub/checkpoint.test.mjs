import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-checkpoint-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { openJournal, appendEntry } = await import("./journal.mjs");
const { buildCheckpoint, verifyCheckpoint, saveCheckpoint, loadCheckpoints, latestCheckpoint } = await import("./checkpoint.mjs");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);

function fixtureEntry(overrides = {}) {
  return {
    period_start: "2026-07-23T00:00:00.000Z",
    period_end: "2026-07-23T00:00:01.000Z",
    reference_db_version: "kernels@2026-07-23",
    triggering_input_digest: "sha256:" + "b".repeat(64),
    humans_involved: [],
    ...overrides,
  };
}

test("checkpoint: builds, signs, and verifies against live journal state", () => {
  const db = openJournal(join(TMP, "cp-a.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "queued" }) });
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "running" }) });

  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors: [] });
  saveCheckpoint(db, checkpoint);

  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true);

  const loaded = loadCheckpoints(db);
  assert.equal(loaded.length, 1);
  assert.equal(latestCheckpoint(db).checkpointSeq, 1);
  db.close();
});

test("checkpoint: carries anchors[] through the signed envelope", () => {
  const db = openJournal(join(TMP, "cp-b.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const anchors = [{ type: "rfc3161", ca: "freetsa", anchored_hash: "sha256:" + "c".repeat(64), der: "ZmFrZQ==" }];
  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors });

  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true);
  assert.deepEqual(result.statement.predicate.anchors, anchors);
  db.close();
});

test("checkpoint: unrecognized anchors[].type is carried through, not rejected", () => {
  const db = openJournal(join(TMP, "cp-c.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const anchors = [{ type: "scitt-receipt-future-typo", note: "must not fail verification" }];
  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors });
  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true);
  db.close();
});

// Tampered negative fixtures (mandatory).
test("negative: tampered envelope fails checkpoint verification", () => {
  const db = openJournal(join(TMP, "cp-d.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors: [] });
  const tampered = { ...checkpoint, envelope: { ...checkpoint.envelope, payload: Buffer.from("{}").toString("base64") } };
  const result = verifyCheckpoint(db, tampered, publicKeys);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "envelope");
  db.close();
});

test("negative: checkpoint verification fails once the journal diverges from what was signed", () => {
  const db = openJournal(join(TMP, "cp-e.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors: [] });
  // Journal advances after the checkpoint was signed.
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "running" }) });
  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "stream_head_mismatch");
  db.close();
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
