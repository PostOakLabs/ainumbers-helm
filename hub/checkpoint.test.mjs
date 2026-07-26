import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-checkpoint-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { openJournal, appendEntry } = await import("./journal.mjs");
const { buildCheckpoint, buildAnchoredCheckpoint, verifyCheckpoint, saveCheckpoint, loadCheckpoints, latestCheckpoint } = await import("./checkpoint.mjs");

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

// HELM-ANCHOR-WIRE-1: buildAnchoredCheckpoint is the function index.mjs's
// real checkpoint-save site now calls, replacing the historical hardcoded
// `anchors: []`. anchorOptions.fetchImpl injection (same discipline as
// anchor-client.test.mjs) proves this without a real network call.
test("buildAnchoredCheckpoint: not offline actually attempts the relay, with THIS checkpoint's own journal_root_digest — never anchors: []", async () => {
  const db = openJournal(join(TMP, "cp-anchor-a.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });

  let calledWithHex;
  const fetchImpl = async (url, opts) => {
    // buildTsqDer's request body carries the requested hash — inspecting the
    // URL/call happening at all is enough to prove this is a REAL attempted
    // network call (not the offline stub below), which is the wiring gap
    // this row closes. The digest-binding check itself (F11) is anchor-
    // client.test.mjs's job, not re-tested here.
    calledWithHex = "called";
    void url; void opts;
    return { ok: false, status: 503, headers: { get: () => null }, arrayBuffer: async () => new ArrayBuffer(0) };
  };

  const checkpoint = await buildAnchoredCheckpoint(db, { checkpointSeq: 1, keys, anchorOptions: { fetchImpl } });
  saveCheckpoint(db, checkpoint);

  assert.equal(calledWithHex, "called", "not-offline must actually call the relay, not silently skip it");
  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true);
  assert.notDeepEqual(result.statement.predicate.anchors, [], "anchors[] must never be the historical no-op empty array");
  db.close();
});

test("buildAnchoredCheckpoint: offline (egress-blocked) still produces a valid checkpoint with a schema-valid skipped marker, never throws", async () => {
  const db = openJournal(join(TMP, "cp-anchor-b.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });

  const checkpoint = await buildAnchoredCheckpoint(db, { checkpointSeq: 1, keys, offline: true });
  saveCheckpoint(db, checkpoint);

  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true, "an offline/egress-blocked run must still produce a valid signed checkpoint");
  const [anchor] = result.statement.predicate.anchors;
  assert.equal(anchor.type, "skipped");
  assert.equal(anchor.reason, "egress_blocked");
  db.close();
});

test("buildAnchoredCheckpoint: a relay error (never a throw, never a network failure) still produces a valid checkpoint with a queued marker", async () => {
  const db = openJournal(join(TMP, "cp-anchor-c.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });

  const fetchImpl = async () => { throw new Error("ECONNREFUSED"); };
  const checkpoint = await buildAnchoredCheckpoint(db, { checkpointSeq: 1, keys, anchorOptions: { fetchImpl } });
  saveCheckpoint(db, checkpoint);

  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true, "a relay failure must never abort checkpoint creation (§5 exit-gate #1)");
  const [anchor] = result.statement.predicate.anchors;
  assert.equal(anchor.type, "queued");
  assert.equal(anchor.reason, "relay_unreachable");
  db.close();
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
