import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openJournal } from "./journal.mjs";
import { createUptimeHeartbeat, isWindowContinuouslyUp, classifyWatchStatus, DEFAULT_UPTIME_HEARTBEAT_MS } from "./uptime-record.mjs";

const TMP = mkdtempSync(join(tmpdir(), "helm-uptime-test-"));

// Fake clock + fake interval, same shape as idle-timer.test.mjs's fakeClock:
// no real setInterval, no flakiness, ticks fire only when the test calls
// advance().
function fakeClock(startMs) {
  let nowMs = startMs;
  let tickFn = null;
  return {
    nowFn: () => nowMs,
    setIntervalFn: (fn) => {
      tickFn = fn;
      return { unref() {} };
    },
    clearIntervalFn: () => {
      tickFn = null;
    },
    advance(ms) {
      nowMs += ms;
      if (tickFn) tickFn();
    },
    // Moves the clock without firing the interval callback — simulates the
    // process dying between ticks (a crash never gets to run its own timer
    // again), as opposed to advance() which models a live process reaching
    // its next scheduled tick.
    advanceSilently(ms) {
      nowMs += ms;
    },
  };
}

test("uptime-record: state 1 — ran (a journal entry exists, regardless of uptime coverage)", () => {
  const db = openJournal(join(TMP, "ran.db"));
  // hasJournalEntryInWindow is the caller's own check (RECEIPT-1's), fed in
  // directly here since this row does not build that query.
  const status = classifyWatchStatus({ hasJournalEntryInWindow: true, continuouslyUp: false });
  assert.equal(status, "ran");
  db.close();
});

test("uptime-record: state 3 — evidence_of_non_run (no journal entry, helmd continuously up the whole window)", () => {
  const db = openJournal(join(TMP, "non-run.db"));
  const clock = fakeClock(Date.parse("2026-08-20T00:00:00.000Z"));
  const heartbeat = createUptimeHeartbeat({ db, intervalMs: 1000, nowFn: clock.nowFn, setIntervalFn: clock.setIntervalFn, clearIntervalFn: clock.clearIntervalFn });
  heartbeat.start();
  const windowStart = clock.nowFn();
  for (let i = 0; i < 5; i++) clock.advance(1000); // five contiguous heartbeats, no gap
  const windowEnd = clock.nowFn();
  heartbeat.stop(); // closes the final interval — the graceful-shutdown half

  const continuouslyUp = isWindowContinuouslyUp(db, { windowStart, windowEnd, toleranceMs: 1000 });
  assert.equal(continuouslyUp, true);
  const status = classifyWatchStatus({ hasJournalEntryInWindow: false, continuouslyUp });
  assert.equal(status, "evidence_of_non_run");
  db.close();
});

test("uptime-record: state 2 — no_evidence_of_run (no journal entry, and a coverage gap — the partition case)", () => {
  const db = openJournal(join(TMP, "no-evidence.db"));
  const clock = fakeClock(Date.parse("2026-08-20T00:00:00.000Z"));
  const heartbeat = createUptimeHeartbeat({ db, intervalMs: 1000, nowFn: clock.nowFn, setIntervalFn: clock.setIntervalFn, clearIntervalFn: clock.clearIntervalFn });
  heartbeat.start();
  const windowStart = clock.nowFn();
  clock.advance(1000);
  heartbeat.stop(); // simulates an abrupt exit's tail (no further heartbeats)... but more importantly:
  // ...no heartbeat ever covers the back half of the window at all — a
  // machine that went to sleep/offline for the rest of the window, phil's
  // partition case: no journal entry AND no uptime record covering the gap.
  const windowEnd = windowStart + 10 * 1000;

  const continuouslyUp = isWindowContinuouslyUp(db, { windowStart, windowEnd, toleranceMs: 1000 });
  assert.equal(continuouslyUp, false);
  const status = classifyWatchStatus({ hasJournalEntryInWindow: false, continuouslyUp });
  assert.equal(status, "no_evidence_of_run");
  db.close();
});

test("uptime-record: a watch that has never had helmd continuously up can never emit a miss — only no_evidence_of_run", () => {
  const db = openJournal(join(TMP, "never-up.db"));
  // No heartbeat ever recorded (fresh install, first boot never completed a
  // tick) — isWindowContinuouslyUp must refuse to claim coverage over an
  // empty record.
  const continuouslyUp = isWindowContinuouslyUp(db, { windowStart: 0, windowEnd: DEFAULT_UPTIME_HEARTBEAT_MS * 10 });
  assert.equal(continuouslyUp, false);
  assert.equal(classifyWatchStatus({ hasJournalEntryInWindow: false, continuouslyUp }), "no_evidence_of_run");
  db.close();
});

test("uptime-record: an abrupt exit (no stop()) leaves the tail of the window uncovered", () => {
  const db = openJournal(join(TMP, "abrupt.db"));
  const clock = fakeClock(Date.parse("2026-08-20T00:00:00.000Z"));
  const heartbeat = createUptimeHeartbeat({ db, intervalMs: 1000, nowFn: clock.nowFn, setIntervalFn: clock.setIntervalFn, clearIntervalFn: clock.clearIntervalFn });
  heartbeat.start();
  const windowStart = clock.nowFn();
  clock.advance(1000);
  clock.advance(1000);
  // process "crashes" here — stop() never called, so the interval since the
  // last tick is never journaled.
  clock.advanceSilently(5000);
  const windowEnd = clock.nowFn();

  const continuouslyUp = isWindowContinuouslyUp(db, { windowStart, windowEnd, toleranceMs: 1000 });
  assert.equal(continuouslyUp, false, "the un-journaled tail after the last tick must not be claimed as covered");
  db.close();
});
