import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-state-snapshot-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateHaIdentity } = await import("./ha-identity.mjs");
const { openJournal, appendEntry } = await import("./journal.mjs");
const {
  initStateSnapshotTables,
  buildStateSnapshot,
  emitStateSnapshot,
  advanceStateHead,
  latestStateSnapshot,
  loadStateSnapshots,
  loadStateHeads,
  provenanceStatus,
} = await import("./state-snapshot.mjs");

const haIdentity = await loadOrCreateHaIdentity();

function fixtureEntry(overrides = {}) {
  return {
    period_start: "2026-08-05T00:00:00.000Z",
    period_end: "2026-08-05T00:00:01.000Z",
    reference_db_version: "kernels@2026-08-05",
    triggering_input_digest: "sha256:" + "b".repeat(64),
    humans_involved: [],
    ...overrides,
  };
}

function freshDb(name) {
  const db = openJournal(join(TMP, name));
  initStateSnapshotTables(db);
  return db;
}

test("state_snapshot: genesis artifact matches §SNAP-1.1 shape, chain.parent_hashes empty", async () => {
  const db = freshDb("snap-a.db");
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });

  const built = await buildStateSnapshot(db, { now: "2026-08-05T00:00:02.000Z", toolVersion: "2026.8.5" });
  assert.equal(built.snapshotSeq, 0);
  assert.equal(built.artifact.mandate_type, "state_snapshot");
  assert.equal(built.artifact.chaingraph_version, "0.4.0");
  assert.deepEqual(built.artifact.chain.parent_hashes, []);
  assert.equal(built.artifact.chain.chain_depth, 0);
  assert.equal(built.artifact.policy_parameters.snapshot_seq, 0);
  assert.equal(built.artifact.output_payload.entry_count, 1);
  assert.equal(built.artifact.output_payload.prev_snapshot_hash, null);
  assert.match(built.artifact.output_payload.state_digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(built.artifact.execution_hash, /^[0-9a-f]{64}$/);
  db.close();
});

test("state_snapshot: second snapshot chains to the first per §SNAP-1.3", async () => {
  const db = freshDb("snap-b.db");
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  const first = await buildStateSnapshot(db, { now: "2026-08-05T00:00:02.000Z" });

  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "running" }) });
  const second = await buildStateSnapshot(db, { now: "2026-08-05T00:00:03.000Z", prev: first });

  assert.equal(second.snapshotSeq, 1);
  assert.deepEqual(second.artifact.chain.parent_hashes, [first.executionHash]);
  assert.equal(second.artifact.chain.chain_depth, 1);
  assert.equal(second.artifact.output_payload.prev_snapshot_hash, "sha256:" + first.executionHash);
  db.close();
});

test("emitStateSnapshot: saves the snapshot and advances a genesis §HEAD-1 head pointing at it", async () => {
  const db = freshDb("snap-c.db");
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });

  const { snapshot, head } = await emitStateSnapshot(db, { haIdentity, now: "2026-08-05T00:00:02.000Z" });
  assert.equal(snapshot.snapshotSeq, 0);
  assert.equal(head.seq, 0);
  assert.equal(head.prev_head_hash, null);
  assert.equal(head.root, "sha256:" + snapshot.executionHash);
  assert.equal(head.signer, haIdentity.id);
  assert.ok(head.proof);

  assert.equal(latestStateSnapshot(db).snapshotSeq, 0);
  assert.equal(loadStateSnapshots(db).length, 1);
  assert.equal(loadStateHeads(db).length, 1);
  db.close();
});

test("emitStateSnapshot: a second boot's emission chains both the snapshot and the head", async () => {
  const db = freshDb("snap-d.db");
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  await emitStateSnapshot(db, { haIdentity, now: "2026-08-05T00:00:02.000Z" });

  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "completed" }) });
  const { snapshot, head } = await emitStateSnapshot(db, { haIdentity, now: "2026-08-05T00:10:00.000Z" });

  assert.equal(snapshot.snapshotSeq, 1);
  assert.equal(head.seq, 1);
  assert.notEqual(head.prev_head_hash, null);
  db.close();
});

test("advanceStateHead: prev_head_hash chains via headHash of the prior head, independent of emitStateSnapshot", async () => {
  const db = freshDb("snap-e.db");
  const headA = await advanceStateHead(db, { executionHashOf: "sha256:" + "a".repeat(64), haIdentity, now: "2026-08-05T00:00:02.000Z" });
  const headB = await advanceStateHead(db, { executionHashOf: "sha256:" + "b".repeat(64), haIdentity, now: "2026-08-05T00:00:03.000Z" });
  assert.equal(headA.seq, 0);
  assert.equal(headB.seq, 1);
  assert.notEqual(headB.prev_head_hash, null);
  db.close();
});

test("provenanceStatus: empty journal has no chain yet", async () => {
  const db = freshDb("snap-f.db");
  const status = await provenanceStatus(db);
  assert.equal(status.has_chain, false);
  assert.equal(status.verified, null);
  db.close();
});

test("provenanceStatus: reports verified:true over a genuine emitted chain", async () => {
  const db = freshDb("snap-g.db");
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  await emitStateSnapshot(db, { haIdentity, now: "2026-08-05T00:00:02.000Z" });
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "completed" }) });
  await emitStateSnapshot(db, { haIdentity, now: "2026-08-05T00:10:00.000Z" });

  const status = await provenanceStatus(db);
  assert.equal(status.has_chain, true);
  assert.equal(status.snapshot_seq, 1);
  assert.equal(status.head_seq, 1);
  assert.equal(status.verified, true);
  assert.deepEqual(status.errors, []);
  db.close();
});

// Tampered negative fixture (mandatory per house convention).
test("negative: provenanceStatus catches a tampered stored head", async () => {
  const db = freshDb("snap-h.db");
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  await emitStateSnapshot(db, { haIdentity, now: "2026-08-05T00:00:02.000Z" });

  // Tamper the stored head's root in place (simulates on-disk corruption).
  const row = db.prepare("SELECT seq, head_json FROM state_heads ORDER BY seq DESC LIMIT 1").get();
  const tampered = { ...JSON.parse(row.head_json), root: "sha256:" + "f".repeat(64) };
  db.prepare("UPDATE state_heads SET head_json = ? WHERE seq = ?").run(JSON.stringify(tampered), row.seq);

  const status = await provenanceStatus(db);
  assert.equal(status.verified, false);
  assert.ok(status.errors.length > 0);
  db.close();
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
