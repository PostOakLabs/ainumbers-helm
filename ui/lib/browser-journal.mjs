// Browser journal (P3-D7, HELM-P3-U2): OPFS is a CACHE, never custody — the
// anchored bundle export is the real archive. This module is split into pure,
// node:test-able pieces (framing, scan/truncate, election, durability check)
// and a thin production adapter over the OPFS sync-access-handle API, which
// only a real browser can exercise (worker glue lives in journal-worker.mjs).
//
// Record framing: [4-byte LE length][32-byte sha256 checksum of payload][payload].
// Scanning stops (and the caller truncates the store to that offset) at the
// first frame that is incomplete or checksum-mismatched — this is what makes
// a kill-mid-write leave the journal openable and valid (spec §5 gate 2).
import { cgCanon } from "./manifest-digest.mjs";

const LEN_BYTES = 4;
const CHECKSUM_BYTES = 32;
const HEADER_BYTES = LEN_BYTES + CHECKSUM_BYTES;

async function sha256(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function encodeEntry(entry) {
  return new TextEncoder().encode(JSON.stringify(cgCanon(entry)));
}

export function decodeEntry(bytes) {
  return JSON.parse(new TextDecoder().decode(bytes));
}

// Frames one payload for append. Pure + async (checksum needs crypto.subtle).
export async function encodeRecord(payloadBytes) {
  const checksum = await sha256(payloadBytes);
  const frame = new Uint8Array(HEADER_BYTES + payloadBytes.length);
  new DataView(frame.buffer).setUint32(0, payloadBytes.length, true);
  frame.set(checksum, LEN_BYTES);
  frame.set(payloadBytes, HEADER_BYTES);
  return frame;
}

// Scans a whole-journal buffer front to back. Returns the decoded payload of
// every valid, complete, checksum-matching record plus the byte offset of the
// end of the last valid record — callers truncate the store to that offset
// so a torn trailing write (or corrupted frame) never resurfaces on reopen.
export async function scanRecords(buffer) {
  const records = [];
  let offset = 0;
  while (offset + HEADER_BYTES <= buffer.length) {
    const view = new DataView(buffer.buffer, buffer.byteOffset + offset, HEADER_BYTES);
    const len = view.getUint32(0, true);
    const recordEnd = offset + HEADER_BYTES + len;
    if (len < 0 || recordEnd > buffer.length) break; // truncated frame (torn write)
    const checksum = buffer.subarray(offset + LEN_BYTES, offset + HEADER_BYTES);
    const payload = buffer.subarray(offset + HEADER_BYTES, recordEnd);
    const expected = await sha256(payload);
    if (!bytesEqual(checksum, expected)) break; // corrupted/torn payload
    records.push(payload);
    offset = recordEnd;
  }
  return { validEnd: offset, records };
}

// --- Storage abstraction -----------------------------------------------
// Matches the shape of OPFS's FileSystemSyncAccessHandle closely enough that
// the same adapter code runs against a real handle or an in-memory test
// double: read(buffer, {at}) -> bytesRead, write(buffer, {at}) -> bytesWritten,
// truncate(len), getSize() -> number, flush(), close().

export class MemoryAccessHandle {
  constructor(initial = new Uint8Array(0)) {
    this._buf = initial;
  }
  getSize() {
    return this._buf.length;
  }
  read(buffer, { at = 0 } = {}) {
    const n = Math.max(0, Math.min(buffer.length, this._buf.length - at));
    if (n > 0) buffer.set(this._buf.subarray(at, at + n));
    return n;
  }
  write(buffer, { at = 0 } = {}) {
    const end = at + buffer.length;
    if (end > this._buf.length) {
      const grown = new Uint8Array(end);
      grown.set(this._buf);
      this._buf = grown;
    }
    this._buf.set(buffer, at);
    return buffer.length;
  }
  truncate(len) {
    if (len >= this._buf.length) return;
    this._buf = this._buf.slice(0, len);
  }
  flush() {}
  close() {}
}

// One dedicated owner (worker) per handle by construction: BrowserJournal
// holds the only reference the caller gives it, and OPFS itself refuses a
// second createSyncAccessHandle on the same file while one is open.
export class BrowserJournal {
  constructor(handle) {
    this.handle = handle;
    this.validEnd = 0;
  }

  // Reads the whole store, validates/truncates to the last good record
  // (torn-write tolerant), and returns the decoded entries plus whether a
  // truncation happened (surfaced to the UI, never hidden).
  async open() {
    const size = this.handle.getSize();
    const buf = new Uint8Array(size);
    this.handle.read(buf, { at: 0 });
    const { validEnd, records } = await scanRecords(buf);
    const truncated = validEnd < size;
    if (truncated) {
      this.handle.truncate(validEnd);
      this.handle.flush();
    }
    this.validEnd = validEnd;
    return { entries: records.map(decodeEntry), truncated };
  }

  async append(entry) {
    const payload = encodeEntry(entry);
    const frame = await encodeRecord(payload);
    this.handle.write(frame, { at: this.validEnd });
    this.handle.flush();
    this.validEnd += frame.length;
    return { offset: this.validEnd };
  }

  close() {
    this.handle.close();
  }
}

// --- Writer election (Web Locks single-writer, second tab = read-only) --

export const WRITER_LOCK_NAME = "helm.browser-journal.writer";

// `locksApi` defaults to navigator.locks in production; tests inject a fake
// implementing the same {request(name, opts, callback)} contract. Resolves
// once a role is decided — "writer" holds the lock until releaseFn() is
// called (typically on pagehide); "reader" means another tab already holds
// it, so this tab must not write.
export function electWriterRole(locksApi) {
  return new Promise((resolve) => {
    let released;
    const held = new Promise((r) => (released = r));
    locksApi
      .request(WRITER_LOCK_NAME, { ifAvailable: true }, (lock) => {
        if (!lock) {
          resolve({ role: "reader", release: () => {} });
          return;
        }
        resolve({ role: "writer", release: () => released() });
        return held; // keep the lock held until release() resolves it
      })
      .catch(() => resolve({ role: "reader", release: () => {} }));
  });
}

// --- Durability check (persisted-storage amber banner) ------------------

// `storageManager` defaults to navigator.storage; tests inject a stub. A
// browser with no Storage API at all (very old/embedded) is treated as
// "not durable" — same banner, since the guarantee can't be confirmed.
export async function isDurable(storageManager) {
  if (!storageManager || typeof storageManager.persisted !== "function") return false;
  try {
    return await storageManager.persisted();
  } catch {
    return false;
  }
}
