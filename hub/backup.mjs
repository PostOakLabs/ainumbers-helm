// Encrypted export/backup + restore (D6/HELM-H3 "done" criteria: restore then
// verify running hashes + checkpoint sigs). A backup is a passphrase-protected
// archive of the full journal + checkpoints tables — portable across machines
// (unlike keys.mjs's vault.key, which is local-only), so the passphrase here
// is always caller-supplied, never the vault passphrase.
import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from "node:crypto";
import { openJournal, replayVerify, withTransaction } from "./journal.mjs";
import { loadCheckpoints, verifyCheckpoint } from "./checkpoint.mjs";

const SCRYPT_KEYLEN = 32;

function encrypt(passphrase, plaintext) {
  const salt = randomBytes(16);
  const key = scryptSync(passphrase, salt, SCRYPT_KEYLEN);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { salt: salt.toString("base64"), iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") };
}

function decrypt(passphrase, blob) {
  const salt = Buffer.from(blob.salt, "base64");
  const key = scryptSync(passphrase, salt, SCRYPT_KEYLEN);
  const iv = Buffer.from(blob.iv, "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(blob.ciphertext, "base64")), decipher.final()]);
}

function dumpAll(db) {
  return {
    journal: db.prepare("SELECT seq, stream_id, kind, run_id, entry_json, entry_digest, rh, created_at FROM journal ORDER BY seq ASC").all(),
    streamState: db.prepare("SELECT stream_id, last_seq, last_rh FROM stream_state ORDER BY stream_id ASC").all(),
    checkpoints: db.prepare("SELECT checkpoint_seq, journal_root_digest, envelope_json, created_at FROM checkpoints ORDER BY checkpoint_seq ASC").all(),
  };
}

// Returns the encrypted blob (JSON-serializable) — caller decides where it lives.
export function exportEncrypted(db, passphrase) {
  const plaintext = Buffer.from(JSON.stringify(dumpAll(db)), "utf8");
  return { format: "helm-journal-backup-v1", ...encrypt(passphrase, plaintext) };
}

// Restores an encrypted export into a fresh database file (must not already
// exist / must be empty — restore is a full replace, never a merge). Returns
// the opened db plus the two integrity checks the WU's "done" criteria require.
export function restoreEncrypted(blob, passphrase, destDbPath) {
  if (blob.format !== "helm-journal-backup-v1") throw new Error(`unknown backup format "${blob.format}"`);
  const dump = JSON.parse(decrypt(passphrase, blob).toString("utf8"));

  const db = openJournal(destDbPath);
  const insertJournal = db.prepare(
    "INSERT INTO journal (seq, stream_id, kind, run_id, entry_json, entry_digest, rh, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  );
  const insertState = db.prepare("INSERT INTO stream_state (stream_id, last_seq, last_rh) VALUES (?, ?, ?)");
  const insertCheckpoint = db.prepare(
    "INSERT INTO checkpoints (checkpoint_seq, journal_root_digest, envelope_json, created_at) VALUES (?, ?, ?, ?)"
  );

  withTransaction(db, () => {
    for (const row of dump.journal) {
      insertJournal.run(row.seq, row.stream_id, row.kind, row.run_id, row.entry_json, row.entry_digest, row.rh, row.created_at);
    }
    for (const row of dump.streamState) insertState.run(row.stream_id, row.last_seq, row.last_rh);
    for (const row of dump.checkpoints) {
      insertCheckpoint.run(row.checkpoint_seq, row.journal_root_digest, row.envelope_json, row.created_at);
    }
  });

  const replay = replayVerify(db);
  const checkpoints = loadCheckpoints(db);
  return { db, replay, checkpoints };
}

// Convenience for the restore test: verify every restored checkpoint against
// the restored journal (not just the newest one) using the H2 public keys.
export function verifyAllCheckpoints(db, checkpoints, publicKeys) {
  return checkpoints.map((cp) => ({ checkpointSeq: cp.checkpointSeq, ...verifyCheckpoint(db, cp, publicKeys) }));
}
