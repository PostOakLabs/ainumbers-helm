// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Browser-side, zero-network mirror of hub/key-lifecycle.mjs's
// verifyKeyLineage() (SIGN-PREROT-1, SIGNING-SURFACES-BUILD-SPEC.md §2). Same
// PAE framing and JCS canonicalization as verify-envelope.mjs, so a
// Node-built key-event chain verifies byte-for-byte identically here — this
// is the "offline continuity verify in the shipped bundle verifier"
// done-criterion: no daemon, no network, WebCrypto Ed25519 only.
import { cgCanon, assertIJson } from "../vendored/hash.mjs";
import { base64ToBytes } from "./verify-envelope.mjs";

const KEY_EVENT_PAYLOAD_TYPE = "application/vnd.helm.key-event+json";
const enc = new TextEncoder();
const dec = new TextDecoder();

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function pae(payloadType, payloadBytes) {
  return concatBytes(
    enc.encode("DSSEv1"), enc.encode(" "),
    enc.encode(String(enc.encode(payloadType).length)), enc.encode(" "), enc.encode(payloadType), enc.encode(" "),
    enc.encode(String(payloadBytes.length)), enc.encode(" "), payloadBytes
  );
}

async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function commitmentOfB64(pubB64) {
  return `sha256:${await sha256Hex(base64ToBytes(pubB64))}`;
}

async function eventDigest(envelope) {
  return `sha256:${await sha256Hex(base64ToBytes(envelope.payload))}`;
}

function decodeEvent(envelope) {
  return JSON.parse(dec.decode(base64ToBytes(envelope.payload)));
}

async function importEd25519(spkiB64) {
  const der = base64ToBytes(spkiB64);
  const raw = der.slice(der.length - 32);
  let bin = "";
  for (const b of raw) bin += String.fromCharCode(b);
  const x = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const jwk = { kty: "OKP", crv: "Ed25519", x };
  return globalThis.crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
}

async function verifySignatureByLabel(envelope, label, publicKeyB64) {
  const entry = (envelope.signatures ?? []).find((s) => s.label === label);
  if (!entry) return false;
  const payloadBytes = base64ToBytes(envelope.payload);
  const toVerify = pae(envelope.payloadType, payloadBytes);
  try {
    const key = await importEd25519(publicKeyB64);
    return await globalThis.crypto.subtle.verify("Ed25519", key, base64ToBytes(entry.sig), toVerify);
  } catch {
    return false;
  }
}

// Sanity-check helper reused by tests / the Verify view: recomputes the JCS
// digest of a canonical object the same way the hub does. Not otherwise used
// by the lineage walk (which only ever hashes already-serialized payload
// bytes, never re-canonicalizes) — exported for parity assertions.
export async function jcsDigestHex(obj) {
  assertIJson(obj);
  const bytes = enc.encode(JSON.stringify(cgCanon(obj)));
  return sha256Hex(bytes);
}

// Mirrors hub/key-lifecycle.mjs verifyKeyLineage() exactly — see that
// module's header for the full algorithm description (inception + rotation
// chain walk, fork detection, replay-as-fork). Only the crypto primitive
// differs (WebCrypto vs node:crypto); the verification logic is identical so
// the two never silently diverge on what counts as valid.
export async function verifyKeyLineage(envelopes) {
  if (!envelopes.length) return { status: "invalid", reason: "empty_chain" };

  const inceptionEnvelope = envelopes[0];
  if (inceptionEnvelope.payloadType !== KEY_EVENT_PAYLOAD_TYPE) {
    return { status: "invalid", reason: "wrong_payload_type" };
  }
  let inceptionEvent;
  try {
    inceptionEvent = decodeEvent(inceptionEnvelope);
  } catch {
    return { status: "invalid", reason: "undecodable_inception" };
  }
  if (inceptionEvent.key_event !== "inception" || inceptionEvent.identity_seq !== 0) {
    return { status: "invalid", reason: "chain_does_not_start_at_inception" };
  }
  if (!(await verifySignatureByLabel(inceptionEnvelope, "self", inceptionEvent.public_key))) {
    return { status: "invalid", reason: "inception_signature_invalid" };
  }

  const rotations = [];
  for (const envelope of envelopes.slice(1)) {
    let event = null;
    try {
      event = decodeEvent(envelope);
    } catch {
      return { status: "invalid", reason: "undecodable_rotation" };
    }
    rotations.push({ envelope, event, digest: await eventDigest(envelope) });
  }

  const rotationsByDigest = new Map(rotations.map((r) => [r.digest, r]));
  const byPrevDigest = new Map();
  for (const r of rotationsByDigest.values()) {
    if (!byPrevDigest.has(r.event.prev_event_digest)) byPrevDigest.set(r.event.prev_event_digest, []);
    byPrevDigest.get(r.event.prev_event_digest).push(r);
  }

  let headDigest = await eventDigest(inceptionEnvelope);
  let headCommitment = inceptionEvent.next_key_commitment;
  let headSeq = 0;
  let currentPublicKeyB64 = inceptionEvent.public_key;
  const trail = [{ kind: "inception", seq: 0, digest: headDigest, publicKey: currentPublicKeyB64 }];

  for (;;) {
    const candidates = byPrevDigest.get(headDigest) ?? [];
    if (candidates.length === 0) break;
    if (candidates.length > 1) {
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
    if ((await commitmentOfB64(event.revealed_public_key)) !== headCommitment) {
      return { status: "invalid", reason: "commitment_mismatch", trail };
    }
    if (!(await verifySignatureByLabel(envelope, "revealed", event.revealed_public_key))) {
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
