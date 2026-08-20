// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-WATCH-UPTIME-1 (HELM-WATCH-BUILD-SPEC.md §1 Q3, §4 row 2). Minimal
// continuous-uptime local record: helmd journals its own "I was up during
// [T1,T2]" heartbeat, so a later freshness check (HELM-WATCH-RECEIPT-1) can
// tell apart "no journal entry because helmd wasn't running to see the gap"
// (no_evidence_of_run) from "no journal entry despite helmd being
// continuously up the whole window" (evidence_of_non_run) — phil's
// partition-safety condition (Q3): a machine asleep or offline must never
// false-fire a miss-event.
//
// This file owns only the heartbeat writer and the coverage/classification
// primitives. Deciding whether an actual watch's window has a journal entry,
// and computing the freshness receipt around that, is HELM-WATCH-RECEIPT-1's
// job — this row does not consume watch-scheduler.mjs at all.
import { appendEntry } from "./journal.mjs";

const UPTIME_STREAM_ID = "helmd_uptime";
export const DEFAULT_UPTIME_HEARTBEAT_MS = 60_000;

function uptimeEntry(periodStartISO, periodEndISO) {
  // No Art. 12 signal is meaningful for a liveness heartbeat (it names no
  // reference DB, is triggered by no input, involves no human) — the three
  // fields are still populated, null/empty, because appendEntry's Art. 12
  // check requires presence, never derives absence for the caller.
  return {
    period_start: periodStartISO,
    period_end: periodEndISO,
    reference_db_version: null,
    triggering_input_digest: null,
    humans_involved: [],
  };
}

function recordUptimeInterval(db, periodStartISO, periodEndISO) {
  return appendEntry(db, {
    streamId: UPTIME_STREAM_ID,
    kind: "uptime_interval",
    entry: uptimeEntry(periodStartISO, periodEndISO),
  });
}

// Journals one [periodStart, periodEnd) interval on every tick, then resets
// periodStart to periodEnd — a running chain of contiguous intervals for as
// long as the daemon is continuously up. stop() closes the final in-progress
// interval, which is the graceful-shutdown half of the record: an abrupt
// exit (crash, kill -9, power loss, sleep) never calls stop(), so the NEXT
// boot's coverage check correctly sees a hole instead of a lie about it.
export function createUptimeHeartbeat({ db, intervalMs = DEFAULT_UPTIME_HEARTBEAT_MS, nowFn = () => Date.now(), setIntervalFn = setInterval, clearIntervalFn = clearInterval }) {
  let timer = null;
  let periodStartMs = null;

  function closeInterval(nowMs) {
    if (periodStartMs === null) return;
    recordUptimeInterval(db, new Date(periodStartMs).toISOString(), new Date(nowMs).toISOString());
    periodStartMs = nowMs;
  }

  function start() {
    if (timer) return;
    periodStartMs = nowFn();
    timer = setIntervalFn(() => closeInterval(nowFn()), intervalMs);
    // Never the reason the process stays alive, same discipline as
    // idle-timer.mjs's own countdown.
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearIntervalFn(timer);
    timer = null;
    closeInterval(nowFn());
    periodStartMs = null;
  }

  return { start, stop };
}

// Reads every helmd_uptime interval overlapping [windowStart, windowEnd] (ms
// epoch) and merges them, tolerating gaps up to `toleranceMs` (default: one
// heartbeat interval — a tick boundary is not itself a liveness gap).
// Returns whether the window is FULLY covered: the Q3 precondition for
// "helmd's own uptime record shows it was continuously running for the full
// window."
export function isWindowContinuouslyUp(db, { windowStart, windowEnd, toleranceMs = DEFAULT_UPTIME_HEARTBEAT_MS }) {
  if (!(windowEnd > windowStart)) throw new Error("uptime-record: windowEnd must be after windowStart");

  const rows = db.prepare("SELECT entry_json FROM journal WHERE stream_id = ? ORDER BY seq ASC").all(UPTIME_STREAM_ID);
  const intervals = rows
    .map((row) => JSON.parse(row.entry_json))
    .map((entry) => [Date.parse(entry.period_start), Date.parse(entry.period_end)])
    .filter(([start, end]) => end > windowStart && start < windowEnd)
    .sort((a, b) => a[0] - b[0]);

  if (intervals.length === 0) return false;
  if (intervals[0][0] > windowStart + toleranceMs) return false;

  let coveredTo = intervals[0][1];
  for (let i = 1; i < intervals.length; i++) {
    const [start, end] = intervals[i];
    if (start > coveredTo + toleranceMs) return false;
    if (end > coveredTo) coveredTo = end;
  }
  return coveredTo >= windowEnd - toleranceMs;
}

// The Q3 distinction itself, as a pure function so both this row's fixture
// and HELM-WATCH-RECEIPT-1's real wiring share one place that draws the
// line. `hasJournalEntryInWindow` is the caller's own "did the watch's pack
// journal a run this window" check (RECEIPT-1's to build); this function
// never queries the run journal itself.
export function classifyWatchStatus({ hasJournalEntryInWindow, continuouslyUp }) {
  if (hasJournalEntryInWindow) return "ran";
  return continuouslyUp ? "evidence_of_non_run" : "no_evidence_of_run";
}
