import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openJournal, appendEntry, streamHead, streamHeads, replayVerify } from "./journal.mjs";

const TMP = mkdtempSync(join(tmpdir(), "helm-journal-test-"));

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

test("journal: append builds a per-stream running hash chain", () => {
  const db = openJournal(join(TMP, "a.db"));
  const e1 = appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "queued" }) });
  const e2 = appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ state: "running" }) });
  assert.ok(e1.seq < e2.seq);
  assert.notEqual(e1.rh, e2.rh);
  const head = streamHead(db, "run-1");
  assert.equal(head.rh, e2.rh);
  assert.equal(head.seq, e2.seq);
  db.close();
});

test("journal: rejects entries missing an Art. 12 named field", () => {
  const db = openJournal(join(TMP, "b.db"));
  const bad = fixtureEntry();
  delete bad.humans_involved;
  assert.throws(() => appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: bad }));
  db.close();
});

test("journal: rejects malformed humans_involved members", () => {
  const db = openJournal(join(TMP, "c.db"));
  assert.throws(() =>
    appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ humans_involved: [{ id_ref: "u1" }] }) })
  );
  db.close();
});

test("journal: independent streams have independent chains", () => {
  const db = openJournal(join(TMP, "d.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry() });
  appendEntry(db, { streamId: "run-2", kind: "execution_state", entry: fixtureEntry() });
  const heads = streamHeads(db);
  assert.equal(heads.length, 2);
  assert.notEqual(heads[0].rh, heads[1].rh);
  db.close();
});

test("journal: replayVerify passes on an untampered journal", () => {
  const db = openJournal(join(TMP, "e.db"));
  for (let i = 0; i < 5; i++) {
    appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ i }) });
  }
  const result = replayVerify(db);
  assert.equal(result.ok, true);
  assert.equal(result.brokenAt, null);
  db.close();
});

// Tampered negative fixture (mandatory per Verifier fixture discipline, §3).
test("negative: replayVerify detects a tampered journal row", () => {
  const db = openJournal(join(TMP, "f.db"));
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ i: 0 }) });
  appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ i: 1 }) });
  db.prepare("UPDATE journal SET entry_digest = ? WHERE seq = 1").run("f".repeat(64));

  const result = replayVerify(db);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt.seq, 1);
  db.close();
});

test("negative: reordering across streams breaks the chain (seq is bound into rh)", () => {
  const db = openJournal(join(TMP, "g.db"));
  const a = appendEntry(db, { streamId: "run-1", kind: "execution_state", entry: fixtureEntry({ i: 0 }) });
  appendEntry(db, { streamId: "run-2", kind: "execution_state", entry: fixtureEntry({ i: 0 }) });
  // Swap run-1's recorded seq to a value it wasn't actually appended at.
  db.prepare("UPDATE journal SET seq = 99 WHERE seq = ?").run(a.seq);
  const result = replayVerify(db);
  assert.equal(result.ok, false);
  db.close();
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
