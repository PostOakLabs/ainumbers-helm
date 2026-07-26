// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-INBOUND-WEBHOOK-1: source-authentication + replay + idempotency
// primitives for the inbound-webhook route. Three DISTINCT concerns, kept
// as three distinct checks per phil's ruling (research/PERSONA-phil-2026-07-26.md
// Option 4) — collapsing any pair of them hides a bypass:
//   1. HMAC-over-raw-body:  proves the caller holds the shared secret.
//   2. nonce+timestamp:     proves this exact call was never seen before
//                           (assertEgressAllowed/HMAC alone can't catch a
//                           byte-for-byte replayed request).
//   3. idempotency key:     lets a LEGITIMATE retry (n8n's built-in
//                           retry-on-failure) return the same result instead
//                           of either double-executing or being rejected as
//                           a replay.
import { createHmac, timingSafeEqual } from "node:crypto";

// --- (1) HMAC over the RAW body, verified BEFORE assertEgressAllowed -------
// header shape: "sha256=<hex>" (GitHub/Stripe convention) or bare hex.
export function verifyWebhookSignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const provided = headerValue.startsWith("sha256=") ? headerValue.slice(7) : headerValue;
  const expectedHex = createHmac("sha256", secret).update(rawBody).digest("hex");
  const expected = Buffer.from(expectedHex, "utf8");
  const actual = Buffer.from(provided, "utf8");
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

// --- (2) replay: timestamp freshness + single-use nonce --------------------
// `requestDigest` (connector.mjs) is a CONTENT hash — a byte-identical
// replayed call produces the identical digest and would be journalled as
// "allowed" a second time. Freshness + single-use-nonce is the freshness
// token that digest was never meant to be.
const NONCE_TOLERANCE_MS = 5 * 60 * 1000;

export function isTimestampFresh(timestamp, toleranceMs = NONCE_TOLERANCE_MS, now = Date.now()) {
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return false;
  return Math.abs(now - t) <= toleranceMs;
}

// Single-use, same discipline as token.mjs's redeemStreamTicket: a nonce
// consumed once can never be consumed again, whether or not it was fresh.
// Unlike a stream ticket (server-minted then redeemed), this nonce is
// CALLER-supplied — so "create" and "redeem" collapse into one atomic
// check-and-consume call. TTL matches the timestamp tolerance window: a
// nonce outside that window is already rejected on freshness, so nothing
// older than the window needs to stay in memory.
const seenNonces = new Map(); // nonce -> expiresAtMs

export function checkAndConsumeNonce(nonce, ttlMs = NONCE_TOLERANCE_MS, now = Date.now()) {
  for (const [key, expiresAt] of seenNonces) {
    if (expiresAt < now) seenNonces.delete(key);
  }
  if (seenNonces.has(nonce)) return false; // replay: already consumed
  seenNonces.set(nonce, now + ttlMs);
  return true;
}

export function __resetNonceStoreForTest() {
  seenNonces.clear();
}

// --- (3) idempotency: distinct from replay ----------------------------------
// A legitimate retry carries the SAME idempotency key as the original call
// but is expected to (and must be allowed to) happen — the opposite of a
// replay, which must always be rejected. Deduped by returning the cached
// response instead of re-invoking the connector/resume path, so a retry
// never re-executes the governed step.
const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const idempotencyCache = new Map(); // key -> { expiresAt, status, body }

export function getIdempotentResponse(key, now = Date.now()) {
  const entry = idempotencyCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt < now) {
    idempotencyCache.delete(key);
    return null;
  }
  return { status: entry.status, body: entry.body };
}

export function storeIdempotentResponse(key, { status, body }, ttlMs = IDEMPOTENCY_TTL_MS, now = Date.now()) {
  idempotencyCache.set(key, { expiresAt: now + ttlMs, status, body });
}

export function __resetIdempotencyStoreForTest() {
  idempotencyCache.clear();
}
