// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-ANCHOR-RETRY-1: anchor-queue.mjs owns retry bookkeeping for the
// markers anchor-client.mjs's anchorForCheckpoint() persists on relay
// failure. These tests exercise the module directly (fetchImpl/now/sleep all
// injected — zero real network, zero real timers) so the rate-limit and
// cooldown behavior is PROVEN, not asserted — this row's own done criterion.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const QUEUE_TMP = mkdtempSync(join(tmpdir(), "helm-anchor-queue-test-"));
process.env.HELM_HOME = QUEUE_TMP;

const {
  loadAnchorQueue, enqueueAnchorRetry, drainAnchorQueue, MIN_RETRY_INTERVAL_MS,
} = await import("./anchor-queue.mjs");
const { buildQueueMarker } = await import("./anchor-client.mjs");

function marker(checkpointSeq, { lastAttemptAt, attempts = 1, journalRootDigest = "a".repeat(64) } = {}) {
  return buildQueueMarker({
    checkpointSeq, status: "queued", reason: "relay_unreachable",
    relayUrl: "https://anchor.ainumbers.co/relay/freetsa",
    attempts, lastAttemptAt, journalRootDigest,
  });
}

// Fake clock: `now()` reads it, `sleep(ms)` advances it instead of actually
// waiting — lets the spacing assertion run in milliseconds of real wall time.
function fakeClock(start) {
  let clock = start;
  return {
    now: () => clock,
    sleep: async (ms) => { clock += ms; },
    advance: (ms) => { clock += ms; },
  };
}

// Each test wants a queue containing EXACTLY the entries it enqueues — the
// tests below intentionally leave un-drained entries behind to prove
// persistence, so the next test starts from a clean file rather than
// inheriting them.
test.beforeEach(() => {
  writeFileSync(join(QUEUE_TMP, "anchor-queue.json"), "[]\n", { mode: 0o600 });
});

test("enqueueAnchorRetry: persists a queued marker; a second call for the same checkpoint replaces, not duplicates", () => {
  enqueueAnchorRetry(marker(101, { lastAttemptAt: new Date(0).toISOString() }));
  enqueueAnchorRetry(marker(101, { lastAttemptAt: new Date(0).toISOString(), attempts: 2 }));
  const entries = loadAnchorQueue().filter((e) => e.checkpoint_seq === 101);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].attempts, 2);
});

test("enqueueAnchorRetry: a status:\"skipped\" marker is never persisted — phil's non-negotiable", () => {
  const skipped = buildQueueMarker({
    checkpointSeq: 202, status: "skipped", reason: "egress_blocked",
    relayUrl: "https://anchor.ainumbers.co/relay/freetsa",
  });
  enqueueAnchorRetry(skipped);
  assert.deepEqual(loadAnchorQueue().filter((e) => e.checkpoint_seq === 202), []);
});

test("drainAnchorQueue: resolves a queued entry on retry success and removes it from the queue", async () => {
  enqueueAnchorRetry(marker(301, { lastAttemptAt: new Date(0).toISOString() }));
  const clock = fakeClock(Date.now());
  let calls = 0;
  const anchorRfc3161Impl = async (digest) => { calls += 1; return { type: "rfc3161", ca: "freetsa", der: "AA==", anchored_hash: `sha256:${digest}` }; };

  const resolved = await drainAnchorQueue({ now: clock.now, sleep: clock.sleep, anchorRfc3161Impl, buildQueueMarkerImpl: buildQueueMarker });

  assert.equal(calls, 1);
  assert.equal(resolved.length, 1);
  assert.equal(resolved[0].checkpointSeq, 301);
  assert.deepEqual(loadAnchorQueue().filter((e) => e.checkpoint_seq === 301), [], "a resolved entry must leave the queue");
});

test("drainAnchorQueue: a retry that fails again stays queued with attempts incremented, never dropped", async () => {
  enqueueAnchorRetry(marker(302, { lastAttemptAt: new Date(0).toISOString(), attempts: 1 }));
  const clock = fakeClock(Date.now());
  const anchorRfc3161Impl = async () => { throw new Error("anchor relay HTTP 503 (freetsa)"); };

  const resolved = await drainAnchorQueue({ now: clock.now, sleep: clock.sleep, anchorRfc3161Impl, buildQueueMarkerImpl: buildQueueMarker });

  assert.equal(resolved.length, 0);
  const entry = loadAnchorQueue().find((e) => e.checkpoint_seq === 302);
  assert.ok(entry, "a repeatedly-failing entry must never be dropped from the queue");
  assert.equal(entry.status, "queued");
  assert.equal(entry.attempts, 2);
  assert.equal(entry.reason, "relay_error");
});

test("drainAnchorQueue: retries two due entries at least MIN_RETRY_INTERVAL_MS apart — rate limit PROVEN, not asserted", async () => {
  enqueueAnchorRetry(marker(401, { lastAttemptAt: new Date(0).toISOString() }));
  enqueueAnchorRetry(marker(402, { lastAttemptAt: new Date(0).toISOString() }));
  const clock = fakeClock(Date.now());
  const callTimes = [];
  const anchorRfc3161Impl = async (digest) => { callTimes.push(clock.now()); return { type: "rfc3161", ca: "freetsa", der: "AA==", anchored_hash: `sha256:${digest}` }; };

  await drainAnchorQueue({ now: clock.now, sleep: clock.sleep, anchorRfc3161Impl, buildQueueMarkerImpl: buildQueueMarker });

  assert.equal(callTimes.length, 2);
  assert.ok(
    callTimes[1] - callTimes[0] >= MIN_RETRY_INTERVAL_MS,
    `second retry must be spaced >= ${MIN_RETRY_INTERVAL_MS}ms after the first (anchor.ainumbers.co's 4 req/min/IP limiter) — got ${callTimes[1] - callTimes[0]}ms`
  );
});

test("drainAnchorQueue: an entry retried more recently than MIN_RETRY_INTERVAL_MS ago is skipped this pass, not dropped", async () => {
  const recent = new Date(Date.now()).toISOString(); // "just now" — inside its own cooldown
  enqueueAnchorRetry(marker(501, { lastAttemptAt: recent }));
  let calls = 0;
  const anchorRfc3161Impl = async () => { calls += 1; return { type: "rfc3161" }; };

  const resolved = await drainAnchorQueue({ anchorRfc3161Impl, buildQueueMarkerImpl: buildQueueMarker });

  assert.equal(calls, 0, "an entry inside its own cooldown must not be retried yet");
  assert.equal(resolved.length, 0);
  assert.ok(loadAnchorQueue().some((e) => e.checkpoint_seq === 501), "the entry must remain queued for a later pass");
});

test.after(() => rmSync(QUEUE_TMP, { recursive: true, force: true }));
