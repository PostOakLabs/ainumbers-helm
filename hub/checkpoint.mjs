// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Signed checkpoints (D6/§26.5): periodic summaries of journal state, signed
// with the H2 dual-sign envelope, optionally carrying anchors[] from
// anchor-client.mjs. checkpoint_seq is caller-assigned (monotonic per hub) —
// this module doesn't own numbering so H4's run engine can key checkpoints to
// its own lifecycle without a second source of truth for "what's next".
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { buildStatement, emitEnvelope, verifyEnvelope, helmPredicateType } from "./envelope.mjs";
import { streamHeads } from "./journal.mjs";
import { anchorForCheckpoint, toCheckpointAnchorEntry } from "./anchor-client.mjs";
import { log } from "./log.mjs";

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

// HELM-ANCHOR-WIRE-1: the last missing step of an otherwise fully-built
// chain — anchorForCheckpoint/verification/failure-handling all shipped
// already (HELM-P3-SEC-3, HELM-ANCHOR-TSR-1), but nothing ever called
// anchorForCheckpoint from a real checkpoint-save site; every checkpoint
// hardcoded `anchors: []`. This is that call.
//
// journal_root_digest depends only on `streams` (see buildCheckpoint above),
// never on checkpointSeq or anchors — so the first build below is a cheap,
// side-effect-free throwaway whose only purpose is handing anchorForCheckpoint
// the digest it needs to anchor BEFORE the real (signed) checkpoint exists.
// The real checkpoint is built a second time, now with the anchor result, and
// is what the caller should sign off as the one to saveCheckpoint().
//
// `offline` is the caller's zero-egress switch (config.anchorOnCheckpoint in
// index.mjs) — anchorForCheckpoint already never throws on a reachable-but-
// failing relay (returns a schema-valid queued/skipped marker instead, per
// §5 exit-gate #1), so this function only ever resolves, never rejects, on
// the anchoring step itself.
export async function buildAnchoredCheckpoint(db, { checkpointSeq, keys, offline = false, anchorOptions = {} }) {
  const { journalRootDigest } = buildCheckpoint(db, { checkpointSeq, keys, anchors: [] });
  const result = await anchorForCheckpoint(journalRootDigest, { checkpointSeq, offline, ...anchorOptions });
  const anchorEntry = toCheckpointAnchorEntry(result);
  log.info(result.anchor ? "checkpoint anchored" : "checkpoint saved without a live anchor", {
    checkpointSeq,
    anchorType: anchorEntry.type,
  });
  return buildCheckpoint(db, { checkpointSeq, keys, anchors: [anchorEntry] });
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

// Verifies the checkpoint's own signature and internal consistency ONLY —
// its envelope signature, and that journal_root_digest actually digests the
// streams it claims to cover. Deliberately does NOT compare against live
// journal state (see verifyCheckpoint below for that): §9.3's boot fast path
// needs to trust a checkpoint that is behind the current head — that's the
// whole point, the rows written since it get replayed forward instead
// (journal.mjs replayVerifyFrom). An unsigned or internally-inconsistent
// checkpoint fails here, which is what forces a full replay at boot.
function verifyCheckpointSelfConsistency(checkpoint, publicKeys) {
  const result = verifyEnvelope(checkpoint.envelope, publicKeys);
  if (!result.valid) return { ...result, valid: false, reason: "envelope" };

  const { predicate } = result.statement;
  const expectedDigest = jcsDigestHex(predicate.streams);
  if (expectedDigest !== predicate.journal_root_digest) {
    return { ...result, valid: false, reason: "journal_root_digest_mismatch" };
  }
  return { ...result, valid: true, reason: null, predicate };
}

export const verifyCheckpointSignature = verifyCheckpointSelfConsistency;

// Verifies the checkpoint envelope AND that its recorded stream heads match
// the journal's current heads for every stream it claims to cover (a
// checkpoint that doesn't match live journal state is stale/tampered, not
// "verified"). Streams absent from the checkpoint are not compared — a
// checkpoint only speaks for the streams it lists. This is the "checkpoint
// matches right now" check (e.g. immediately after taking one); it is NOT
// what boot uses, since boot's whole point is trusting a checkpoint that's
// behind the live head — see verifyCheckpointSignature + replayVerifyFrom.
export function verifyCheckpoint(db, checkpoint, publicKeys) {
  const self = verifyCheckpointSelfConsistency(checkpoint, publicKeys);
  if (!self.valid) return self;

  const live = new Map(streamHeads(db).map((s) => [s.stream_id, s]));
  for (const claimed of self.predicate.streams) {
    const current = live.get(claimed.stream_id);
    if (!current || current.seq !== claimed.journal_seq || current.rh !== claimed.rh) {
      return { ...self, valid: false, reason: "stream_head_mismatch", streamId: claimed.stream_id };
    }
  }
  return { ...self, valid: true, reason: null };
}
