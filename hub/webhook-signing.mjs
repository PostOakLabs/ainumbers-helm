// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Outbound push delivery signing (HELM-PUSH-HMAC-1). Stripe-webhook-shape
// HMAC over helmd's OUTBOUND deliveries — distinct from artifact signing
// (SSHSIG/minisign, SIGN-EXTSIG-1) and from the OCG envelope/execution_hash;
// this only proves "this delivery came from this helmd instance and the
// body wasn't altered in transit," nothing about the payload's truth.
// node:crypto only — no third-party signing library.
import { createHmac, timingSafeEqual } from "node:crypto";

const DEFAULT_TOLERANCE_SECONDS = 300; // 5 minutes
const DEFAULT_DEDUPE_WINDOW_SECONDS = 300;

function hmacHex(secret, message) {
  return createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

// body must be the exact raw bytes/string being sent on the wire — sign
// after serialization, never a re-serialized copy of an object.
export function signWebhookPayload(secret, body, timestamp = Math.floor(Date.now() / 1000)) {
  if (!secret) throw new Error("webhook-signing: secret is required");
  if (typeof body !== "string" && !Buffer.isBuffer(body)) {
    throw new Error("webhook-signing: body must be a string or Buffer (the exact bytes sent)");
  }
  const signedMessage = `${timestamp}.${body}`;
  return `t=${timestamp},v1=${hmacHex(secret, signedMessage)}`;
}

function parseSignatureHeader(header) {
  if (typeof header !== "string") return null;
  const parts = Object.fromEntries(
    header.split(",").map((kv) => {
      const idx = kv.indexOf("=");
      return idx === -1 ? [kv, ""] : [kv.slice(0, idx).trim(), kv.slice(idx + 1).trim()];
    })
  );
  if (!parts.t || !parts.v1) return null;
  if (!/^\d+$/.test(parts.t)) return null;
  return { timestamp: Number(parts.t), signature: parts.v1 };
}

// Returns { ok: true } or { ok: false, reason }. Never throws on a bad
// signature/header/timestamp — those are expected adversarial inputs.
export function verifyWebhookSignature(secret, header, body, opts = {}) {
  const toleranceSeconds = opts.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  const parsed = parseSignatureHeader(header);
  if (!parsed) return { ok: false, reason: "malformed signature header" };

  if (Math.abs(now - parsed.timestamp) > toleranceSeconds) {
    return { ok: false, reason: `timestamp outside tolerance window (${toleranceSeconds}s)` };
  }

  const expected = hmacHex(secret, `${parsed.timestamp}.${body}`);
  const expectedBuf = Buffer.from(expected, "utf8");
  const gotBuf = Buffer.from(parsed.signature, "utf8");
  const same = expectedBuf.length === gotBuf.length && timingSafeEqual(expectedBuf, gotBuf);
  if (!same) return { ok: false, reason: "signature mismatch" };

  return { ok: true, timestamp: parsed.timestamp };
}

// Bounded-window replay guard for the receiving side: rejects an event id
// seen again inside windowSeconds, and never grows unbounded (each
// checkAndRecord call prunes entries whose window has expired).
export function createEventDedupe({ windowSeconds = DEFAULT_DEDUPE_WINDOW_SECONDS } = {}) {
  const seen = new Map(); // eventId -> expiry (unix seconds)

  return {
    // Returns true the first time eventId is seen inside the window (accept),
    // false on a replay (reject).
    checkAndRecord(eventId, now = Math.floor(Date.now() / 1000)) {
      for (const [id, expiry] of seen) {
        if (expiry <= now) seen.delete(id);
      }
      if (seen.has(eventId)) return false;
      seen.set(eventId, now + windowSeconds);
      return true;
    },
    size() {
      return seen.size;
    },
  };
}
