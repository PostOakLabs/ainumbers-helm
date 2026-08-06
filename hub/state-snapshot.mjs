// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// PROV-SNAP-HELM-1: helmd's own dogfood of SPEC.md §SNAP-1/§HEAD-1 — the
// first real, non-test surface for those primitives. Every boot that has
// journal streams emits ONE state_snapshot v0.4 artifact
// (mandate_type:"state_snapshot") over the journal's own stream heads,
// chains it to the prior snapshot (§SNAP-1.3), and advances a §HEAD-1
// head-commit whose root is that snapshot's execution_hash (§SNAP-1.4). Same
// cadence and fire-and-forget discipline as checkpoint.mjs's boot-time
// advance (index.mjs) — never gates daemon readiness on this write finishing.
import { createHash } from "node:crypto";
import { cgCanon, assertIJson, executionHash } from "./vendored/ocg/kernels/_hash.mjs";
import { buildHead, signHead, headHash, verifyChain, didKeyToPublicKey } from "./vendored/ocg/kernels/_head.mjs";
import { streamHeads } from "./journal.mjs";

const TOOL_ID = "helmd-state-snapshot";
const STATE_SCHEMA = "https://ainumbers.co/helm/state-schema/v1#journal-stream-heads";
const CAPTURE_SCOPE = "journal_stream_heads";
const STREAM = "helmd:state-snapshot";

function jcsSha256Hex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

export function initStateSnapshotTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS state_snapshots (
      snapshot_seq INTEGER PRIMARY KEY,
      artifact_json TEXT NOT NULL,
      execution_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS state_heads (
      seq INTEGER PRIMARY KEY,
      head_json TEXT NOT NULL,
      head_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);
}

export function latestStateSnapshot(db) {
  const row = db
    .prepare("SELECT snapshot_seq AS snapshotSeq, artifact_json AS artifactJson, execution_hash AS executionHash FROM state_snapshots ORDER BY snapshot_seq DESC LIMIT 1")
    .get();
  return row ? { snapshotSeq: row.snapshotSeq, artifact: JSON.parse(row.artifactJson), executionHash: row.executionHash } : null;
}

export function loadStateSnapshots(db) {
  return db
    .prepare("SELECT snapshot_seq AS snapshotSeq, artifact_json AS artifactJson, execution_hash AS executionHash FROM state_snapshots ORDER BY snapshot_seq ASC")
    .all()
    .map((row) => ({ snapshotSeq: row.snapshotSeq, artifact: JSON.parse(row.artifactJson), executionHash: row.executionHash }));
}

function saveStateSnapshot(db, { snapshotSeq, artifact, executionHash: hash }) {
  db.prepare("INSERT INTO state_snapshots (snapshot_seq, artifact_json, execution_hash, created_at) VALUES (?, ?, ?, ?)").run(
    snapshotSeq,
    JSON.stringify(artifact),
    hash,
    new Date().toISOString()
  );
}

export function latestStateHead(db) {
  const row = db.prepare("SELECT head_json AS headJson FROM state_heads ORDER BY seq DESC LIMIT 1").get();
  return row ? JSON.parse(row.headJson) : null;
}

export function loadStateHeads(db) {
  return db
    .prepare("SELECT head_json AS headJson FROM state_heads ORDER BY seq ASC")
    .all()
    .map((row) => JSON.parse(row.headJson));
}

function saveStateHead(db, head, hash) {
  db.prepare("INSERT INTO state_heads (seq, head_json, head_hash, created_at) VALUES (?, ?, ?, ?)").run(
    head.seq,
    JSON.stringify(head),
    hash,
    new Date().toISOString()
  );
}

// Builds (unsigned — a state_snapshot artifact carries no per-artifact
// signature of its own; §HEAD-1's head-commit is the signed, mutable tip
// over the stream, per §SNAP-1.4) the next state_snapshot artifact over the
// journal's current stream heads — §SNAP-1.1's shape exactly, using the SAME
// executionHash() every OCG kernel artifact hashes with (RIDER-KERNEL: ONE
// canonical hash path, never a second canonicalization).
export async function buildStateSnapshot(db, { now, prev = null, toolVersion } = {}) {
  const streams = streamHeads(db).map(({ stream_id, seq, rh }) => ({ stream_id, seq, rh }));
  const stateDoc = { streams };
  const stateDigest = "sha256:" + jcsSha256Hex(stateDoc);
  const snapshotSeq = (prev?.snapshotSeq ?? -1) + 1;
  const prevChainDepth = prev?.artifact?.chain?.chain_depth ?? -1;

  const policy_parameters = { state_schema: STATE_SCHEMA, capture_scope: CAPTURE_SCOPE, snapshot_seq: snapshotSeq };
  const output_payload = {
    state_digest: stateDigest,
    entry_count: streams.length,
    // §SNAP-1.1 spells this field "sha256:<hex> or null" — prefixed, unlike
    // chain.parent_hashes below (bare hex, the existing kernel convention:
    // executionHash() already returns bare hex and every kernel's
    // buildArtifact feeds it straight into chain.parent_hashes unprefixed).
    prev_snapshot_hash: prev ? "sha256:" + prev.executionHash : null,
  };
  const hash = await executionHash(policy_parameters, output_payload);
  const generatedAt = now ?? new Date().toISOString();

  const artifact = {
    "@context": "https://ainumbers.co/chaingraph/context/v0.3/context.jsonld",
    chaingraph_version: "0.4.0",
    mandate_type: "state_snapshot",
    tool_id: TOOL_ID,
    tool_version: toolVersion ?? "0",
    generated_at: generatedAt,
    execution_hash: hash,
    chain: {
      parent_hashes: prev ? [prev.executionHash] : [],
      parent_tool_ids: prev ? [TOOL_ID] : [],
      chain_depth: prevChainDepth + 1,
    },
    policy_parameters,
    output_payload,
    compliance_flags: ["EU_AI_ACT_ART12_RECORD_KEEPING"],
    compute_mode: "server",
    audit_signature: { payloadType: "application/vnd.openchain.graph+json;version=0.4", payload: "", signatures: [] },
  };
  return { snapshotSeq, artifact, executionHash: hash };
}

// Advances the §HEAD-1 head-commit whose root is the latest snapshot's
// execution_hash (§SNAP-1.4 — the snapshot stream's mutable tip). haIdentity
// is helmd's OWN ha-identity.mjs keypair (WebCrypto Ed25519 + did:key) — the
// same identity that signs an HA replay countersignature, reused here rather
// than minting a third keypair for what is, structurally, the same "helmd
// attesting to something it computed itself" act. `executionHashOf` is a
// bare-hex execution_hash (the kernel convention) — §HEAD-1.0's `root` MUST
// be "sha256:"-prefixed, so it's prefixed here, once, at the one call site.
export async function advanceStateHead(db, { executionHashOf, haIdentity, now }) {
  const prevHead = latestStateHead(db);
  const seq = prevHead ? prevHead.seq + 1 : 0;
  const prevHash = prevHead ? await headHash(prevHead) : null;
  const timestamp = now ?? new Date().toISOString();
  const unsigned = buildHead({
    stream: STREAM,
    signer: haIdentity.id,
    seq,
    prev_head_hash: prevHash,
    root: "sha256:" + executionHashOf,
    timestamp,
  });
  const signed = await signHead(unsigned, {
    verificationMethod: haIdentity.id,
    created: timestamp,
    privateKey: haIdentity.privateKey,
  });
  saveStateHead(db, signed, await headHash(signed));
  return signed;
}

// Boot-time (or on-demand) advance: build the next snapshot over current
// journal state, save it, then advance the head to point at it. Mirrors
// checkpoint.mjs's buildAnchoredCheckpoint+saveCheckpoint pairing and
// index.mjs's fire-and-forget call discipline at the boot-time call site —
// never awaited by the boot path itself, a failure here logs and never
// brings the daemon down (see index.mjs's checkpoint block for the same
// pattern applied to checkpoints).
export async function emitStateSnapshot(db, { haIdentity, now, toolVersion } = {}) {
  const prev = latestStateSnapshot(db);
  const built = await buildStateSnapshot(db, { now, prev, toolVersion });
  saveStateSnapshot(db, built);
  const head = await advanceStateHead(db, { executionHashOf: built.executionHash, haIdentity, now });
  return { snapshot: built, head };
}

// GET /provenance/head's data source — the daemon's own live chain-verify
// status, i.e. the "helm UI shows chain-verify status" half of this WU's
// row. resolveKey uses didKeyToPublicKey directly (a did:key is
// self-certifying — no external key store needed) since helmd is the only
// signer this stream will ever have.
export async function provenanceStatus(db) {
  const heads = loadStateHeads(db);
  const latestSnapshot = latestStateSnapshot(db);
  if (heads.length === 0) {
    return { has_chain: false, snapshot_seq: null, head_seq: null, verified: null, errors: [] };
  }
  const verify = await verifyChain(heads, { resolveKey: (did) => didKeyToPublicKey(did) });
  return {
    has_chain: true,
    snapshot_seq: latestSnapshot?.snapshotSeq ?? null,
    head_seq: heads[heads.length - 1].seq,
    verified: verify.valid,
    errors: verify.errors,
  };
}
