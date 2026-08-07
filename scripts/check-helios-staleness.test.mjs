// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// Unit tests for the Helios pin-staleness decision function. Deliberately
// pure/offline: scripts/test.mjs runs every *.test.mjs on every push, so this
// file must never touch the network. The live end-to-end check (does the pin
// actually still match a16z/helios's latest release) is exercised by running
// check-helios-staleness.mjs itself, by hand, per the file header.
import { test } from "node:test";
import assert from "node:assert/strict";
import { compareSemver, evaluateStaleness, parseSemver } from "./check-helios-staleness.mjs";

test("parseSemver accepts bare MAJOR.MINOR.PATCH and rejects everything else", () => {
  assert.deepEqual(parseSemver("0.11.1"), [0, 11, 1]);
  assert.equal(parseSemver("v0.11.1"), null);
  assert.equal(parseSemver("0.11.1-rc1"), null);
  assert.equal(parseSemver(undefined), null);
});

test("compareSemver orders numerically, not lexically", () => {
  assert.equal(compareSemver([0, 9, 2], [0, 11, 1]), -1);
  assert.equal(compareSemver([0, 11, 1], [0, 11, 1]), 0);
  assert.equal(compareSemver([0, 12, 0], [0, 11, 1]), 1);
});

test("OK: pin matches upstream latest exactly (the real 2026-08-07 condition)", () => {
  const r = evaluateStaleness({
    pinnedTag: "0.11.1",
    latestRelease: { tagName: "0.11.1", publishedAt: "2026-02-27T21:24:53Z" },
  });
  assert.equal(r.status, "OK");
  assert.equal(r.failing, false);
});

test("OK: pin ahead of upstream (should not happen, but not this gate's alarm)", () => {
  const r = evaluateStaleness({
    pinnedTag: "0.12.0",
    latestRelease: { tagName: "0.11.1", publishedAt: "2026-02-27T21:24:53Z" },
  });
  assert.equal(r.status, "OK");
  assert.equal(r.failing, false);
});

test("PIN-STALE: reported, never failing — advisory only, never auto-fixed", () => {
  const r = evaluateStaleness({
    pinnedTag: "0.9.2",
    latestRelease: { tagName: "0.11.1", publishedAt: "2026-02-27T21:24:53Z" },
  });
  assert.equal(r.status, "PIN-STALE");
  assert.equal(r.failing, false);
  assert.equal(r.pinned, "0.9.2");
  assert.equal(r.latest, "0.11.1");
});

test("UPSTREAM-UNREACHABLE fails rather than silently passing", () => {
  const r = evaluateStaleness({ pinnedTag: "0.11.1", fetchError: "HTTP 503" });
  assert.equal(r.status, "UPSTREAM-UNREACHABLE");
  assert.equal(r.failing, true);
});

test("PIN-UNPARSEABLE fails when our own config is malformed", () => {
  const r = evaluateStaleness({
    pinnedTag: "not-a-version",
    latestRelease: { tagName: "0.11.1" },
  });
  assert.equal(r.status, "PIN-UNPARSEABLE");
  assert.equal(r.failing, true);
});

test("UPSTREAM-NO-RELEASE fails when a16z/helios has no releases at all", () => {
  const r = evaluateStaleness({ pinnedTag: "0.11.1", latestRelease: null });
  assert.equal(r.status, "UPSTREAM-NO-RELEASE");
  assert.equal(r.failing, true);
});

test("UPSTREAM-TAG-UNPARSEABLE does not fail — an unexpected upstream tag shape is not our defect", () => {
  const r = evaluateStaleness({
    pinnedTag: "0.11.1",
    latestRelease: { tagName: "nightly-build" },
  });
  assert.equal(r.status, "UPSTREAM-TAG-UNPARSEABLE");
  assert.equal(r.failing, false);
});

// phil review nit (HELIOS-VENDOR-1): a malicious/MITM'd upstream response
// could embed terminal escape sequences in tag_name. evaluateStaleness itself
// just passes strings through — the stripping happens in fetchLatestRelease,
// which is not unit-testable offline (it calls fetch). This test pins the
// decision function's behavior on an already-hostile string to document that
// the field is opaque data to evaluateStaleness, never interpreted.
test("evaluateStaleness treats latestRelease.tagName as opaque data, even if hostile", () => {
  const r = evaluateStaleness({
    pinnedTag: "0.11.1",
    latestRelease: { tagName: "\x1b[2J0.11.1" },
  });
  assert.equal(r.status, "UPSTREAM-TAG-UNPARSEABLE");
  assert.equal(r.failing, false);
});
