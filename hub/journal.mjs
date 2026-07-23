// Append-only journal (D6, HELM-H3). One SQLite table, one process, one writer
// (better-sqlite3 is synchronous — no concurrent-writer races to guard against).
//
// Per-stream running hash (SPEC-S26 §26.5):
//   rh_0     = SHA-256(stream_id)
//   rh_n     = SHA-256(rh_{n-1} || stream_id || journal_seq || entry_digest)
// journal_seq is the GLOBAL monotonic row id (not per-stream) so the hash also
// binds each stream's position in the overall append order — reordering rows
// across streams (not just within one) breaks the chain.
//
// Every entry MUST carry the four EU AI Act Art. 12(2)/(3) named field groups
// (period_start, period_end, reference_db_version, triggering_input_digest,
// humans_involved[]) POPULATED by the caller — this module never derives them.
// Zero-dep by design (STANDING ORDERS #10 — never npm): uses the Node builtin
// node:sqlite (DatabaseSync, stable since Node 22.5) instead of an npm native
// module. `engines.node` in package.json already requires >=22.
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";

const ART12_FIELDS = ["period_start", "period_end", "reference_db_version", "triggering_input_digest", "humans_involved"];

function sha256Hex(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest("hex");
}

function jcsBytes(obj) {
  assertIJson(obj);
  return Buffer.from(JSON.stringify(cgCanon(obj)), "utf8");
}

// node:sqlite's DatabaseSync has no .transaction() helper (unlike
// better-sqlite3) — wrap BEGIN/COMMIT/ROLLBACK by hand. Exported so backup.mjs
// (a separate multi-statement writer) doesn't have to re-invent it.
export function withTransaction(db, fn) {
  db.exec("BEGIN");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

export function openJournal(dbPath) {
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS journal (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      stream_id TEXT NOT NULL,
      kind TEXT NOT NULL,
      run_id TEXT,
      entry_json TEXT NOT NULL,
      entry_digest TEXT NOT NULL,
      rh TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_journal_stream ON journal(stream_id, seq);
    CREATE TABLE IF NOT EXISTS stream_state (
      stream_id TEXT PRIMARY KEY,
      last_seq INTEGER NOT NULL,
      last_rh TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS checkpoints (
      checkpoint_seq INTEGER PRIMARY KEY,
      journal_root_digest TEXT NOT NULL,
      envelope_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
  return db;
}

function streamSeed(streamId) {
  return sha256Hex(Buffer.from(streamId, "utf8"));
}

function assertArt12(entry) {
  for (const f of ART12_FIELDS) {
    if (!(f in entry)) throw new Error(`journal entry missing Art. 12 field "${f}"`);
  }
  if (!Array.isArray(entry.humans_involved)) throw new Error('journal entry "humans_involved" must be an array (MAY be empty, MUST be present)');
  for (const h of entry.humans_involved) {
    if (!h || typeof h.id_ref !== "string" || typeof h.role !== "string") {
      throw new Error('journal entry "humans_involved[]" members must be {id_ref, role}');
    }
  }
}

// entry: { kind, run_id?, ...Art.12 fields, ...kind-specific payload } — caller-populated, not derived.
export function appendEntry(db, { streamId, kind, runId = null, entry }) {
  assertArt12(entry);
  const fullEntry = { kind, run_id: runId, ...entry };
  const entryDigest = sha256Hex(jcsBytes(fullEntry));

  const prior = db.prepare("SELECT last_seq, last_rh FROM stream_state WHERE stream_id = ?").get(streamId);
  const rhPrev = prior ? prior.last_rh : streamSeed(streamId);

  const insert = db.prepare(
    "INSERT INTO journal (stream_id, kind, run_id, entry_json, entry_digest, rh, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
  );
  const upsertState = db.prepare(
    "INSERT INTO stream_state (stream_id, last_seq, last_rh) VALUES (?, ?, ?) " +
      "ON CONFLICT(stream_id) DO UPDATE SET last_seq = excluded.last_seq, last_rh = excluded.last_rh"
  );

  return withTransaction(db, () => {
    // seq is assigned by SQLite's AUTOINCREMENT; reserve it with a placeholder
    // insert-then-hash step so rh can bind the real seq value.
    const info = insert.run(streamId, kind, runId, JSON.stringify(fullEntry), entryDigest, "", new Date().toISOString());
    const seq = info.lastInsertRowid;
    const rh = sha256Hex(
      Buffer.from(rhPrev, "hex"),
      Buffer.from(streamId, "utf8"),
      Buffer.from(String(seq), "utf8"),
      Buffer.from(entryDigest, "hex")
    );
    db.prepare("UPDATE journal SET rh = ? WHERE seq = ?").run(rh, seq);
    upsertState.run(streamId, seq, rh);
    return { seq, rh, entryDigest };
  });
}

export function streamHead(db, streamId) {
  const row = db.prepare("SELECT last_seq, last_rh FROM stream_state WHERE stream_id = ?").get(streamId);
  return row ? { seq: row.last_seq, rh: row.last_rh } : { seq: null, rh: streamSeed(streamId) };
}

export function streamHeads(db) {
  return db.prepare("SELECT stream_id, last_seq AS seq, last_rh AS rh FROM stream_state ORDER BY stream_id").all();
}

// Replay every stream from seq 1 and recompute rh independently of the stored
// column — this is the integrity check run on daemon restart (D6) and the
// mechanism a tampered-journal negative fixture is proven against.
export function replayVerify(db) {
  const rows = db.prepare("SELECT seq, stream_id, entry_digest, rh FROM journal ORDER BY seq ASC").all();
  const rhByStream = new Map();
  for (const row of rows) {
    const rhPrev = rhByStream.get(row.stream_id) ?? streamSeed(row.stream_id);
    const expected = sha256Hex(
      Buffer.from(rhPrev, "hex"),
      Buffer.from(row.stream_id, "utf8"),
      Buffer.from(String(row.seq), "utf8"),
      Buffer.from(row.entry_digest, "hex")
    );
    if (expected !== row.rh) {
      return { ok: false, brokenAt: { seq: row.seq, streamId: row.stream_id, expected, found: row.rh } };
    }
    rhByStream.set(row.stream_id, expected);
  }
  return { ok: true, brokenAt: null };
}
