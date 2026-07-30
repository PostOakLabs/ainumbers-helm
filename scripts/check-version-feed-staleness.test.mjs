// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// Unit tests for the version-feed staleness gate's decision function.
// Deliberately pure: scripts/test.mjs runs every *.test.mjs in the repo on
// every push, so this file must never touch the network or shell out to `gh`.
// The live end-to-end proof that the gate fires belongs to the scheduled
// workflow run, not to this suite.
import { test } from "node:test";
import assert from "node:assert/strict";
import { compareCalVer, evaluateFeed, parseCalVer } from "./check-version-feed-staleness.mjs";

const NOW = new Date("2026-07-30T00:00:00Z");
const OLD = new Date("2026-07-28T14:00:00Z"); // well outside the 45-minute grace

test("parseCalVer accepts bare CalVer and rejects everything else", () => {
  assert.deepEqual(parseCalVer("2026.7.28"), [2026, 7, 28]);
  assert.equal(parseCalVer("v0.1.0"), null);
  assert.equal(parseCalVer("2026.7.28-rc1"), null);
  assert.equal(parseCalVer(undefined), null);
});

test("compareCalVer orders numerically, not lexically", () => {
  // The bug this pins: "2026.7.9" > "2026.7.28" under string comparison.
  assert.equal(compareCalVer([2026, 7, 9], [2026, 7, 28]), -1);
  assert.equal(compareCalVer([2026, 7, 28], [2026, 7, 28]), 0);
  assert.equal(compareCalVer([2026, 8, 1], [2026, 7, 28]), 1);
});

// The live condition on 2026-07-30, re-derived from gh + curl while building
// this gate: tags 2026.7.25/.26/.27/.28 all reachable on main, and
// https://ainumbers.co/helm/version.json advertising 2026.7.25.
test("FEED-STALE: the real 2026-07-30 condition fails loudly", () => {
  const r = evaluateFeed({
    newestTag: { name: "2026.7.28", pushedAt: OLD },
    feed: { latest_version: "2026.7.25" },
    now: NOW,
  });
  assert.equal(r.status, "FEED-STALE");
  assert.equal(r.failing, true);
});

test("OK: feed level with the newest tag is silent", () => {
  const r = evaluateFeed({
    newestTag: { name: "2026.7.28", pushedAt: OLD },
    feed: { latest_version: "2026.7.28" },
    now: NOW,
  });
  assert.equal(r.status, "OK");
  assert.equal(r.failing, false);
});

test("OK: a feed AHEAD of the newest tag is not this gate's alarm", () => {
  const r = evaluateFeed({
    newestTag: { name: "2026.7.25", pushedAt: OLD },
    feed: { latest_version: "2026.7.28" },
    now: NOW,
  });
  assert.equal(r.status, "OK");
  assert.equal(r.failing, false);
});

test("SKIPPED-GRACE: a tag pushed minutes ago is reported, not failed", () => {
  const r = evaluateFeed({
    newestTag: { name: "2026.7.28", pushedAt: new Date(NOW.getTime() - 5 * 60 * 1000) },
    feed: { latest_version: "2026.7.25" },
    now: NOW,
  });
  assert.equal(r.status, "SKIPPED-GRACE");
  assert.equal(r.failing, false);
});

// "I could not look" must never read as "all clear" — that is the defect class
// this work unit exists to remove.
test("FEED-UNREACHABLE fails rather than passing", () => {
  const r = evaluateFeed({
    newestTag: { name: "2026.7.28", pushedAt: OLD },
    feedError: "HTTP 503",
    now: NOW,
  });
  assert.equal(r.status, "FEED-UNREACHABLE");
  assert.equal(r.failing, true);
});

test("FEED-NO-VERSION fails when latest_version is absent or malformed", () => {
  assert.equal(
    evaluateFeed({ newestTag: { name: "2026.7.28", pushedAt: OLD }, feed: {}, now: NOW }).failing,
    true,
  );
  assert.equal(
    evaluateFeed({
      newestTag: { name: "2026.7.28", pushedAt: OLD },
      feed: { latest_version: "v0.1.0" },
      now: NOW,
    }).status,
    "FEED-NO-VERSION",
  );
});

test("FEED-UNPARSEABLE fails when the body is not a JSON object", () => {
  const r = evaluateFeed({ newestTag: { name: "2026.7.28", pushedAt: OLD }, feed: null, now: NOW });
  assert.equal(r.status, "FEED-UNPARSEABLE");
  assert.equal(r.failing, true);
});

test("NO-TAG-TO-COMPARE is silent — the tag/release half owns tag-shaped problems", () => {
  const r = evaluateFeed({ newestTag: null, feed: { latest_version: "2026.7.25" }, now: NOW });
  assert.equal(r.status, "NO-TAG-TO-COMPARE");
  assert.equal(r.failing, false);
});
