// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Pre-rotation key lifecycle (KERI-borrow, no KERI protocol, no witnesses —
// SIGN-PREROT-1, SIGNING-SURFACES-BUILD-SPEC.md §2). Each identity's key
// history is a chain of signed events:
//   inception: self-signed by key_0, commits SHA-256(key_1's public key)
//   rotation:  signed by the REVEALED key (the one the prior event committed
//              to, and optionally co-signed by the outgoing key while still
//              valid), commits SHA-256(next key), links prev_event_digest to
//              the prior event.
// Continuity from any earlier state to the current key is verifiable offline
// by walking the chain and checking, at each link: (a) the revealed public
// key hashes to the prior event's commitment, (b) the rotation event is
// signed by that same revealed key. There is no witness set and no
// consensus — a FORK (two rotations both claiming the same prior commitment,
// i.e. equivocation) is DETECTED and reported, never adjudicated: fork
// RESOLUTION is the banned ordering service (memory
// project-ainumbers-corda-tripwires). SHA-256 + Ed25519 only, both existing
// node:crypto paths — zero new primitives (phil GO).
//
// This module owns event construction + verification only. Persisting events
// (e.g. appending them to hub/journal.mjs as kind "key_inception"/
// "key_rotation" journal entries) is the caller's concern — deliberately kept
// out of this file to share no state with HELM-KEYCHAIN-1's storage module
// (custody vs lifecycle, per the build spec's cross-reference note).
import { generateKeyPairSync, createPublicKey, sign as cryptoSign, verify as cryptoVerify, createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";

export const KEY_EVENT_PAYLOAD_TYPE = "application/vnd.helm.key-event+json";

function sha256Hex(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function jcsBytes(obj) {
  assertIJson(obj);
  return Buffer.from(JSON.stringify(cgCanon(obj)), "utf8");
}

// Same DSSE Pre-Authentication Encoding shape as hub/envelope.mjs, binding
// payloadType into what gets signed so a signature can't be replayed across
// payload types (e.g. a checkpoint signature reused as a key-event signature).
function pae(payloadType, payloadBytes) {
  const enc = (s) => Buffer.from(s, "utf8");
  return Buffer.concat([
    enc("DSSEv1"), enc(" "),
    enc(String(Buffer.byteLength(payloadType, "utf8"))), enc(" "), enc(payloadType), enc(" "),
    enc(String(payloadBytes.length)), enc(" "), payloadBytes,
  ]);
}

function spkiB64(publicKey) {
  return publicKey.export({ format: "der", type: "spki" }).toString("base64");
}

function commitmentOfDer(der) {
  return `sha256:${sha256Hex(der)}`;
}

export function commitmentOf(publicKey) {
  return commitmentOfDer(publicKey.export({ format: "der", type: "spki" }));
}

function commitmentOfB64(pubB64) {
  return commitmentOfDer(Buffer.from(pubB64, "base64"));
}

export function generateLifecycleKeyPair() {
  return generateKeyPairSync("ed25519");
}

// signers: [{ label, privateKey }] Ed25519 KeyObjects. One signature entry
// per signer, each independently verifiable (never a combined/aggregate sig).
function envelopeEvent(event, signers) {
  const payloadBytes = jcsBytes(event);
  const toSign = pae(KEY_EVENT_PAYLOAD_TYPE, payloadBytes);
  const signatures = signers.map(({ label, privateKey }) => ({
    label,
    alg: "EdDSA",
    sig: cryptoSign(null, toSign, privateKey).toString("base64"),
  }));
  return { payloadType: KEY_EVENT_PAYLOAD_TYPE, payload: payloadBytes.toString("base64"), signatures };
}

function decodeEvent(envelope) {
  return JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
}

// Digest of the CANONICAL PAYLOAD (not the whole envelope incl. signatures)
// so a reader who only has the decoded event body can still re-derive the
// same linkage digest a signature-stripped export would carry.
export function eventDigest(envelope) {
  return `sha256:${sha256Hex(Buffer.from(envelope.payload, "base64"))}`;
}

function verifySignatureByLabel(envelope, label, publicKeyB64) {
  const entry = (envelope.signatures ?? []).find((s) => s.label === label);
  if (!entry) return false;
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  const toVerify = pae(envelope.payloadType, payloadBytes);
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(publicKeyB64, "base64"), format: "der", type: "spki" });
  } catch {
    return false;
  }
  try {
    return cryptoVerify(null, toVerify, key, Buffer.from(entry.sig, "base64"));
  } catch {
    return false;
  }
}

// identityId: caller-assigned stable label for this key's lineage (e.g. a
// journal stream_id). currentKeys signs its own inception (self-certifying,
// standard for a genesis event with no prior key to defer to).
export function buildInceptionEvent({ identityId, currentKeys, nextPublicKey, createdAt = new Date().toISOString() }) {
  const event = {
    key_event: "inception",
    identity_id: identityId,
    identity_seq: 0,
    public_key: spkiB64(currentKeys.publicKey),
    next_key_commitment: commitmentOf(nextPublicKey),
    created_at: createdAt,
  };
  return envelopeEvent(event, [{ label: "self", privateKey: currentKeys.privateKey }]);
}

// priorEnvelope: the inception or rotation event this rotation follows.
// revealedKeys: the keypair whose PUBLIC half matches priorEnvelope's
// next_key_commitment — MUST sign (that's the whole continuity proof).
// outgoingPrivateKey: OPTIONAL co-signature from the key being retired, while
// still held and considered valid (phil §2: "and the outgoing key where
// still valid") — absence is legal (the outgoing key may already be
// destroyed) and never fails verification on its own.
export function buildRotationEvent({
  identityId,
  identitySeq,
  priorEnvelope,
  revealedKeys,
  nextPublicKey,
  outgoingPrivateKey = null,
  createdAt = new Date().toISOString(),
}) {
  const event = {
    key_event: "rotation",
    identity_id: identityId,
    identity_seq: identitySeq,
    prev_event_digest: eventDigest(priorEnvelope),
    revealed_public_key: spkiB64(revealedKeys.publicKey),
    next_key_commitment: commitmentOf(nextPublicKey),
    created_at: createdAt,
  };
  const signers = [{ label: "revealed", privateKey: revealedKeys.privateKey }];
  if (outgoingPrivateKey) signers.push({ label: "outgoing", privateKey: outgoingPrivateKey });
  return envelopeEvent(event, signers);
}

// Walks a full chain of key-event envelopes (inception first; rotations in
// any order — order is DERIVED from prev_event_digest linkage, not from
// array position, so a caller can hand this an unordered export). Never
// throws on a malformed/tampered/forked chain — every failure mode is a
// typed return value so a caller (or the offline bundle verifier) can render
// it instead of catching an exception.
//
// Returns one of three shapes, discriminated by `status`:
//   "continuous"    — clean walk from genesis to the current head.
//   "fork_detected" — walk was clean up to `forkAt`, then found >=1 competing
//                      next-events off the same head. Both/all competitors
//                      are named; NEITHER is picked — adjudication refused.
//   "invalid"        — a cryptographic or structural break (bad signature,
//                      commitment mismatch, doesn't start at inception).
// A stale/replayed rotation (one whose prev_event_digest names a PAST,
// already-superseded head instead of the live one — an attempt to roll the
// identity back to an earlier key) surfaces as "fork_detected" the moment the
// walk reaches the head it collides with: it is, structurally, a fork with
// exactly one honest branch. See assertRotationAppendable below for the
// write-time guard that stops one from ever being persisted in the first
// place.
export function verifyKeyLineage(envelopes) {
  if (!envelopes.length) return { status: "invalid", reason: "empty_chain" };

  const inceptionEnvelope = envelopes[0];
  let inceptionEvent;
  try {
    inceptionEvent = decodeEvent(inceptionEnvelope);
  } catch {
    return { status: "invalid", reason: "undecodable_inception" };
  }
  if (inceptionEvent.key_event !== "inception" || inceptionEvent.identity_seq !== 0) {
    return { status: "invalid", reason: "chain_does_not_start_at_inception" };
  }
  if (!verifySignatureByLabel(inceptionEnvelope, "self", inceptionEvent.public_key)) {
    return { status: "invalid", reason: "inception_signature_invalid" };
  }

  const rotations = envelopes.slice(1).map((envelope) => {
    try {
      return { envelope, event: decodeEvent(envelope), digest: eventDigest(envelope) };
    } catch {
      return { envelope, event: null, digest: eventDigest(envelope) };
    }
  });
  if (rotations.some((r) => r.event === null)) {
    return { status: "invalid", reason: "undecodable_rotation" };
  }

  // Dedupe by digest first — a byte-identical event submitted twice (a benign
  // resend/retry) is one candidate, not two; only DISTINCT events competing
  // for the same prev_event_digest constitute a fork.
  const rotationsByDigest = new Map(rotations.map((r) => [r.digest, r]));
  const byPrevDigest = new Map();
  for (const r of rotationsByDigest.values()) {
    if (!byPrevDigest.has(r.event.prev_event_digest)) byPrevDigest.set(r.event.prev_event_digest, []);
    byPrevDigest.get(r.event.prev_event_digest).push(r);
  }

  let headDigest = eventDigest(inceptionEnvelope);
  let headCommitment = inceptionEvent.next_key_commitment;
  let headSeq = 0;
  let currentPublicKeyB64 = inceptionEvent.public_key;
  const trail = [{ kind: "inception", seq: 0, digest: headDigest, publicKey: currentPublicKeyB64 }];

  for (;;) {
    const candidates = byPrevDigest.get(headDigest) ?? [];
    if (candidates.length === 0) break;
    if (candidates.length > 1) {
      // Any rotation whose prev_event_digest lands on a head the walk already
      // passed through — including a "roll back to an old key" attempt built
      // off an ancestor commitment — surfaces HERE, at the head it collides
      // with, the moment the walk reaches that head. There is no separate
      // later case to detect: a stale/replayed rotation is just a fork with
      // exactly one honest branch, refused the same as any other equivocation.
      return {
        status: "fork_detected",
        forkAt: headDigest,
        competing: candidates.map((c) => c.digest),
        trail,
        currentPublicKeyB64,
      };
    }
    const { envelope, event, digest } = candidates[0];
    if (event.identity_seq !== headSeq + 1) {
      return { status: "invalid", reason: "sequence_gap", expectedSeq: headSeq + 1, gotSeq: event.identity_seq, trail };
    }
    if (commitmentOfB64(event.revealed_public_key) !== headCommitment) {
      return { status: "invalid", reason: "commitment_mismatch", trail };
    }
    if (!verifySignatureByLabel(envelope, "revealed", event.revealed_public_key)) {
      return { status: "invalid", reason: "revealed_key_signature_invalid", trail };
    }
    headDigest = digest;
    headCommitment = event.next_key_commitment;
    headSeq = event.identity_seq;
    currentPublicKeyB64 = event.revealed_public_key;
    trail.push({ kind: "rotation", seq: headSeq, digest: headDigest, publicKey: currentPublicKeyB64 });
  }

  return {
    status: "continuous",
    headSeq,
    headDigest,
    currentPublicKeyB64,
    nextKeyCommitment: headCommitment,
    trail,
  };
}

// Write-time guard: is `candidateEnvelope` a legal NEXT rotation given the
// identity's current, already-verified head? This is the concrete mechanism
// behind "an old rotation event cannot be replayed to roll back" — a stale
// rotation event (one whose prev_event_digest names an ancestor the identity
// has already moved past) fails the digest-equality check below, exactly
// like presenting a stale compare-and-swap token. Callers persisting new
// rotation events (journal.mjs appendEntry, or an equivalent store) MUST
// call this before accepting one; verifyKeyLineage above audits an already-
// accepted history and cannot by itself stop a bad write.
// currentHead: { digest, seq, commitment, publicKeyB64 } — e.g. the last
// element of a verifyKeyLineage() trail, translated by the caller.
export function assertRotationAppendable(currentHead, candidateEnvelope) {
  const event = decodeEvent(candidateEnvelope);
  if (event.key_event !== "rotation") {
    throw new Error(`key-lifecycle: expected a rotation event, got "${event.key_event}"`);
  }
  if (event.prev_event_digest !== currentHead.digest) {
    throw new Error(
      `key-lifecycle: rotation rejected — prev_event_digest does not match the current head ` +
        `(stale/replayed event, or an attempt to fork/roll back the identity)`
    );
  }
  if (event.identity_seq !== currentHead.seq + 1) {
    throw new Error(`key-lifecycle: rotation rejected — identity_seq ${event.identity_seq} is not current+1 (${currentHead.seq + 1})`);
  }
  if (commitmentOfB64(event.revealed_public_key) !== currentHead.commitment) {
    throw new Error("key-lifecycle: rotation rejected — revealed_public_key does not hash to the recorded next_key_commitment");
  }
  if (!verifySignatureByLabel(candidateEnvelope, "revealed", event.revealed_public_key)) {
    throw new Error("key-lifecycle: rotation rejected — not validly signed by the revealed key");
  }
  return true;
}

export { spkiB64, commitmentOfB64, decodeEvent };
