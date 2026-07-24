import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  MemoryAccessHandle,
  BrowserJournal,
  encodeEntry,
  encodeRecord,
  scanRecords,
  electWriterRole,
  isDurable,
} from "./browser-journal.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

function fixtureEntry(overrides = {}) {
  return { period_start: "2026-07-24T00:00:00.000Z", state: "queued", ...overrides };
}

test("browser-journal: append then open round-trips entries in order", async () => {
  const journal = new BrowserJournal(new MemoryAccessHandle());
  await journal.append(fixtureEntry({ i: 0 }));
  await journal.append(fixtureEntry({ i: 1 }));
  const { entries, truncated } = await journal.open();
  assert.equal(truncated, false);
  assert.deepEqual(entries.map((e) => e.i), [0, 1]);
});

test("browser-journal: kill-mid-write (torn trailing frame) opens valid, truncates cleanly", async () => {
  const handle = new MemoryAccessHandle();
  const journal = new BrowserJournal(handle);
  await journal.append(fixtureEntry({ i: 0 }));
  const goodSize = handle.getSize();
  // Simulate a crash mid-write of a second record: append a well-formed
  // header claiming a long payload, but only some of the payload bytes land.
  const partial = await encodeRecord(encodeEntry(fixtureEntry({ i: 1 })));
  handle.write(partial.subarray(0, partial.length - 5), { at: goodSize });

  const reopened = new BrowserJournal(handle);
  const { entries, truncated } = await reopened.open();
  assert.equal(truncated, true);
  assert.deepEqual(entries.map((e) => e.i), [0]);
  assert.equal(handle.getSize(), goodSize); // torn tail discarded from the store itself

  // Chain intact: a fresh append after recovery lands right after the last
  // valid record, and a third open sees both.
  await reopened.append(fixtureEntry({ i: 2 }));
  const third = new BrowserJournal(handle);
  const { entries: finalEntries, truncated: finalTruncated } = await third.open();
  assert.equal(finalTruncated, false);
  assert.deepEqual(finalEntries.map((e) => e.i), [0, 2]);
});

test("negative: corrupted checksum on a fully-present frame is treated as torn, not silently accepted", async () => {
  const handle = new MemoryAccessHandle();
  const journal = new BrowserJournal(handle);
  await journal.append(fixtureEntry({ i: 0 }));
  const frame = await encodeRecord(encodeEntry(fixtureEntry({ i: 1 })));
  frame[4] ^= 0xff; // flip a checksum byte
  handle.write(frame, { at: handle.getSize() });

  const { entries, truncated } = await new BrowserJournal(handle).open();
  assert.equal(truncated, true);
  assert.deepEqual(entries.map((e) => e.i), [0]);
});

test("scanRecords: empty buffer yields no records and validEnd 0", async () => {
  const { validEnd, records } = await scanRecords(new Uint8Array(0));
  assert.equal(validEnd, 0);
  assert.equal(records.length, 0);
});

test("writer election: lock available -> writer role, hold survives until release", async () => {
  let released = false;
  const fakeLocks = {
    request(name, opts, cb) {
      assert.equal(name, "helm.browser-journal.writer");
      assert.equal(opts.ifAvailable, true);
      const p = Promise.resolve(cb({ name }));
      return p.then(() => new Promise((r) => setTimeout(r, 0))).then(() => { released = true; });
    },
  };
  const { role, release } = await electWriterRole(fakeLocks);
  assert.equal(role, "writer");
  release();
});

test("writer election: lock held elsewhere (ifAvailable callback gets null) -> reader role", async () => {
  const fakeLocks = {
    request(name, opts, cb) {
      return Promise.resolve(cb(null));
    },
  };
  const { role } = await electWriterRole(fakeLocks);
  assert.equal(role, "reader");
});

test("writer election: locksApi throwing/rejecting degrades to reader, never throws", async () => {
  const fakeLocks = { request: () => Promise.reject(new Error("no Web Locks in this context")) };
  const { role } = await electWriterRole(fakeLocks);
  assert.equal(role, "reader");
});

test("isDurable: true when storageManager.persisted() resolves true", async () => {
  assert.equal(await isDurable({ persisted: async () => true }), true);
});

test("isDurable: false when persisted() resolves false", async () => {
  assert.equal(await isDurable({ persisted: async () => false }), false);
});

test("isDurable: false (not a dead end) when storageManager is absent or throws", async () => {
  assert.equal(await isDurable(undefined), false);
  assert.equal(await isDurable({ persisted: async () => { throw new Error("nope"); } }), false);
});
