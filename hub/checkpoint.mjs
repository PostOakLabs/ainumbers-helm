// Signed checkpoints (D6/§26.5): periodic summaries of journal state, signed
// with the H2 dual-sign envelope, optionally carrying anchors[] from
// anchor-client.mjs. checkpoint_seq is caller-assigned (monotonic per hub) —
// this module doesn't own numbering so H4's run engine can key checkpoints to
// its own lifecycle without a second source of truth for "what's next".
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { buildStatement, emitEnvelope, verifyEnvelope, helmPredicateType } from "./envelope.mjs";
import { streamHeads } from "./journal.mjs";

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

// anchors: array of anchor-client.mjs results ({type, ...}), or [] — checkpoints
// SHOULD be anchored per §20 but an unanchored checkpoint is still a valid,
// verifiable signed object (anchoring can lag or retry independently).
export function buildCheckpoint(db, { checkpointSeq, keys, anchors = [] }) {
  const streams = streamHeads(db).map(({ stream_id, seq, rh }) => ({ stream_id, journal_seq: seq, rh }));
  const journalRootDigest = jcsDigestHex(streams);

  const predicate = { checkpoint_seq: checkpointSeq, streams, journal_root_digest: journalRootDigest, anchors };
  const statement = buildStatement({
    subject: [{ name: "journal_root", digest: { sha256: journalRootDigest } }],
    predicateType: helmPredicateType("checkpoint"),
    predicate,
  });

  const envelope = emitEnvelope(statement, keys);
  return { checkpointSeq, journalRootDigest, envelope };
}

export function saveCheckpoint(db, checkpoint) {
  db.prepare(
    "INSERT INTO checkpoints (checkpoint_seq, journal_root_digest, envelope_json, created_at) VALUES (?, ?, ?, ?)"
  ).run(checkpoint.checkpointSeq, checkpoint.journalRootDigest, JSON.stringify(checkpoint.envelope), new Date().toISOString());
}

export function loadCheckpoints(db) {
  return db
    .prepare("SELECT checkpoint_seq AS checkpointSeq, journal_root_digest AS journalRootDigest, envelope_json FROM checkpoints ORDER BY checkpoint_seq ASC")
    .all()
    .map((row) => ({ checkpointSeq: row.checkpointSeq, journalRootDigest: row.journalRootDigest, envelope: JSON.parse(row.envelope_json) }));
}

export function latestCheckpoint(db) {
  const row = db
    .prepare("SELECT checkpoint_seq AS checkpointSeq, journal_root_digest AS journalRootDigest, envelope_json FROM checkpoints ORDER BY checkpoint_seq DESC LIMIT 1")
    .get();
  return row ? { checkpointSeq: row.checkpointSeq, journalRootDigest: row.journalRootDigest, envelope: JSON.parse(row.envelope_json) } : null;
}

// Verifies the checkpoint envelope AND that its recorded stream heads match
// the journal's current heads for every stream it claims to cover (a
// checkpoint that doesn't match live journal state is stale/tampered, not
// "verified"). Streams absent from the checkpoint are not compared — a
// checkpoint only speaks for the streams it lists.
export function verifyCheckpoint(db, checkpoint, publicKeys) {
  const result = verifyEnvelope(checkpoint.envelope, publicKeys);
  if (!result.valid) return { ...result, valid: false, reason: "envelope" };

  const { predicate } = result.statement;
  const expectedDigest = jcsDigestHex(predicate.streams);
  if (expectedDigest !== predicate.journal_root_digest) {
    return { ...result, valid: false, reason: "journal_root_digest_mismatch" };
  }

  const live = new Map(streamHeads(db).map((s) => [s.stream_id, s]));
  for (const claimed of predicate.streams) {
    const current = live.get(claimed.stream_id);
    if (!current || current.seq !== claimed.journal_seq || current.rh !== claimed.rh) {
      return { ...result, valid: false, reason: "stream_head_mismatch", streamId: claimed.stream_id };
    }
  }
  return { ...result, valid: true, reason: null };
}
