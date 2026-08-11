// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  signWebhookPayload,
  verifyWebhookSignature,
  createEventDedupe,
} from "./webhook-signing.mjs";

const SECRET = "whsec_test_secret";

test("sign/verify round trip: a freshly signed delivery verifies ok", () => {
  const body = JSON.stringify({ event: "run.completed", runId: "run-1" });
  const now = 1_700_000_000;
  const header = signWebhookPayload(SECRET, body, now);

  assert.match(header, /^t=\d+,v1=[0-9a-f]{64}$/);
  const result = verifyWebhookSignature(SECRET, header, body, { now });
  assert.deepEqual(result, { ok: true, timestamp: now });
});

test("tampered signature is rejected", () => {
  const body = "hello";
  const now = 1_700_000_000;
  const header = signWebhookPayload(SECRET, body, now);
  const tampered = header.replace(/v1=[0-9a-f]+/, "v1=" + "0".repeat(64));

  const result = verifyWebhookSignature(SECRET, tampered, body, { now });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "signature mismatch");
});

test("tampered body is rejected (signature no longer matches)", () => {
  const body = "hello";
  const now = 1_700_000_000;
  const header = signWebhookPayload(SECRET, body, now);

  const result = verifyWebhookSignature(SECRET, header, "hello-modified", { now });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "signature mismatch");
});

test("stale timestamp outside the tolerance window is rejected", () => {
  const body = "hello";
  const signedAt = 1_700_000_000;
  const header = signWebhookPayload(SECRET, body, signedAt);

  const tooLate = signedAt + 301; // default tolerance is 300s
  const result = verifyWebhookSignature(SECRET, header, body, { now: tooLate });
  assert.equal(result.ok, false);
  assert.match(result.reason, /tolerance window/);
});

test("a timestamp inside a custom tolerance window still verifies", () => {
  const body = "hello";
  const signedAt = 1_700_000_000;
  const header = signWebhookPayload(SECRET, body, signedAt);

  const result = verifyWebhookSignature(SECRET, header, body, {
    now: signedAt + 590,
    toleranceSeconds: 600,
  });
  assert.equal(result.ok, true);
});

test("malformed header is rejected without throwing", () => {
  assert.equal(verifyWebhookSignature(SECRET, "garbage", "body").ok, false);
  assert.equal(verifyWebhookSignature(SECRET, "t=abc,v1=xyz", "body").ok, false);
  assert.equal(verifyWebhookSignature(SECRET, null, "body").ok, false);
});

test("wrong secret is rejected", () => {
  const body = "hello";
  const now = 1_700_000_000;
  const header = signWebhookPayload(SECRET, body, now);
  const result = verifyWebhookSignature("wrong-secret", header, body, { now });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "signature mismatch");
});

test("event-id dedupe: first delivery accepted, replay inside the window rejected", () => {
  const dedupe = createEventDedupe({ windowSeconds: 300 });
  const now = 1_700_000_000;

  assert.equal(dedupe.checkAndRecord("evt-1", now), true);
  assert.equal(dedupe.checkAndRecord("evt-1", now + 10), false, "replay with a valid signature must still be rejected");
  assert.equal(dedupe.checkAndRecord("evt-2", now + 10), true, "a different event id is unaffected");
});

test("event-id dedupe window is bounded: expired entries are pruned, not retained forever", () => {
  const dedupe = createEventDedupe({ windowSeconds: 300 });
  const now = 1_700_000_000;

  dedupe.checkAndRecord("evt-1", now);
  assert.equal(dedupe.size(), 1);

  // Past the window: evt-1 both expires from storage AND is legitimately
  // re-deliverable (Stripe-shape semantics — the window bounds retention,
  // it doesn't promise infinite replay protection).
  assert.equal(dedupe.checkAndRecord("evt-1", now + 301), true);
  assert.equal(dedupe.size(), 1, "pruned the expired entry before recording the new one");
});
