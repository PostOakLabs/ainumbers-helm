// Live-network test gate.
//
// Some tests exercise REAL third-party services (FreeTSA RFC 3161 relays,
// public OpenTimestamps calendars). Those are genuine coverage, but a
// third-party hiccup during a post-merge `main` run turns the branch red for
// a reason that has nothing to do with the diff — exactly how HELM-P2-S10
// (#32) reddened main (FreeTSA was up during PR CI, flaky at merge time).
//
// So: the blocking `node scripts/test.mjs` suite must be DETERMINISTIC and
// OFFLINE. Any test that reaches the network wraps its declaration in
// `liveTest(...)` instead of `test(...)`. By default it SKIPS (not fails);
// set HELM_LIVE_NET=1 (the non-blocking live CI job / a local check) to run it.
//
// Precedent: hub/vendored/ocg/kernels/anchor-binding.test.mjs already went
// 100% offline with a one-time regen step. This generalizes that discipline.
import { test } from "node:test";

export const LIVE_NET = process.env.HELM_LIVE_NET === "1";

const SKIP_REASON = "live-network test — set HELM_LIVE_NET=1 to run (kept out of the blocking suite so third-party flakiness can't redden main)";

// Same call shapes as node:test's `test`: (name, fn) or (name, opts, fn).
export function liveTest(name, opts, fn) {
  if (typeof opts === "function") {
    fn = opts;
    opts = {};
  }
  const skip = LIVE_NET ? (opts.skip ?? false) : SKIP_REASON;
  return test(name, { ...opts, skip }, fn);
}
