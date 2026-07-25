// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX-BUILD-SPEC.md §12.5: the mechanism that makes the §12.1 drift
// (VIEWS / STATIC_VIEWS / hand-written <nav> as three unsynced lists)
// unrepeatable. Without this test §12 is decoration.
import { test } from "node:test";
import assert from "node:assert/strict";
import { TABS } from "./tab-meta.mjs";
import { VIEWS } from "./view-registry.mjs";

test("tab-meta: TABS ids and VIEWS keys are the same set", () => {
  const tabIds = new Set(TABS.map((t) => t.id));
  const viewIds = new Set(Object.keys(VIEWS));
  assert.deepEqual([...tabIds].sort(), [...viewIds].sort());
});

test("tab-meta: every intro is non-empty and at most 150 characters", () => {
  for (const tab of TABS) {
    assert.ok(typeof tab.intro === "string" && tab.intro.length > 0, `${tab.id}: intro must be non-empty`);
    assert.ok(tab.intro.length <= 150, `${tab.id}: intro is ${tab.intro.length} chars, must be <= 150`);
  }
});

test("tab-meta: every requiresPairing is an explicit boolean", () => {
  for (const tab of TABS) {
    assert.equal(typeof tab.requiresPairing, "boolean", `${tab.id}: requiresPairing must be an explicit boolean`);
  }
});
