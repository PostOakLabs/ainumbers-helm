// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// §18 idle shutdown: helmd exits after DEFAULT_IDLE_TIMEOUT_MS of no
// authenticated activity. Generic timer, deliberately knowing nothing about
// SSE/runs/pairing/backups — index.mjs wires those in as `isSuppressed`, the
// same shape a future suppression condition can extend without touching this
// file.
export const DEFAULT_IDLE_TIMEOUT_MS = 120_000;

// A suppressed check doesn't cancel the countdown, it defers the DECISION —
// re-checking on the same cadence keeps the exit close to "timeoutMs after
// the daemon actually went idle" instead of waiting a full extra `timeoutMs`
// after the suppressing condition (an open SSE tab, say) clears.
export function createIdleTimer({ timeoutMs, isSuppressed, onIdle, setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout }) {
  let timer = null;

  function check() {
    if (isSuppressed()) {
      schedule();
      return;
    }
    onIdle();
  }

  function schedule() {
    if (timer) clearTimeoutFn(timer);
    timer = setTimeoutFn(check, timeoutMs);
    // Never the reason the process stays alive — the HTTP server socket
    // already does that job, and unref lets tests exit without an explicit
    // stop() on every path.
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearTimeoutFn(timer);
    timer = null;
  }

  // Called on every authenticated request (§18.2) — restarts the countdown
  // from full rather than merely un-suppressing it.
  function reset() {
    schedule();
  }

  return { reset, stop };
}
