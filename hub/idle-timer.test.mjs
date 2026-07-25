import { test } from "node:test";
import assert from "node:assert/strict";
import { createIdleTimer } from "./idle-timer.mjs";

// Fake clock: setTimeoutFn/clearTimeoutFn are injected so the suite never
// depends on wall-clock timing (no real setTimeout, no flakiness).
function fakeClock() {
  let pending = null;
  return {
    setTimeoutFn: (fn) => {
      pending = fn;
      return { unref() {} };
    },
    clearTimeoutFn: () => {
      pending = null;
    },
    fire() {
      const fn = pending;
      pending = null;
      if (fn) fn();
    },
    hasPending: () => pending !== null,
  };
}

test("fires onIdle when not suppressed", () => {
  const clock = fakeClock();
  let fired = 0;
  const timer = createIdleTimer({
    timeoutMs: 1000,
    isSuppressed: () => false,
    onIdle: () => fired++,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
  timer.reset();
  clock.fire();
  assert.equal(fired, 1);
});

test("re-schedules instead of firing while suppressed", () => {
  const clock = fakeClock();
  let fired = 0;
  let suppressed = true;
  const timer = createIdleTimer({
    timeoutMs: 1000,
    isSuppressed: () => suppressed,
    onIdle: () => fired++,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
  timer.reset();
  clock.fire();
  assert.equal(fired, 0);
  assert.equal(clock.hasPending(), true);
  suppressed = false;
  clock.fire();
  assert.equal(fired, 1);
});

test("reset restarts the countdown, cancelling a pending check", () => {
  const clock = fakeClock();
  let fired = 0;
  const timer = createIdleTimer({
    timeoutMs: 1000,
    isSuppressed: () => false,
    onIdle: () => fired++,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
  timer.reset();
  timer.reset();
  assert.equal(clock.hasPending(), true);
  clock.fire();
  assert.equal(fired, 1);
});

test("stop cancels the pending check", () => {
  const clock = fakeClock();
  let fired = 0;
  const timer = createIdleTimer({
    timeoutMs: 1000,
    isSuppressed: () => false,
    onIdle: () => fired++,
    setTimeoutFn: clock.setTimeoutFn,
    clearTimeoutFn: clock.clearTimeoutFn,
  });
  timer.reset();
  timer.stop();
  assert.equal(clock.hasPending(), false);
});
