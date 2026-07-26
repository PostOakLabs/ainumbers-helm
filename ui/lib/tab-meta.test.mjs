// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-UX-BUILD-SPEC.md §12.5: the mechanism that makes the §12.1 drift
// (VIEWS / STATIC_VIEWS / hand-written <nav> as three unsynced lists)
// unrepeatable. Without this test §12 is decoration.
import { test } from "node:test";
import assert from "node:assert/strict";
import { TABS } from "./tab-meta.mjs";
import { VIEWS } from "./view-registry.mjs";

test("tab-meta: routable TABS ids (disabled: true excluded) and VIEWS keys are the same set", () => {
  // HELM-UX2-J-AGENTS-SLOT (§19): a `disabled: true` tab is a reserved nav
  // slot with deliberately no route and no view — excluding it here is the
  // gate's job, not an escape hatch, since the whole point of §19 is "no
  // placeholder content, no empty tab."
  const tabIds = new Set(TABS.filter((t) => !t.disabled).map((t) => t.id));
  const viewIds = new Set(Object.keys(VIEWS));
  assert.deepEqual([...tabIds].sort(), [...viewIds].sort());
});

test("tab-meta: every disabled tab has no matching VIEWS entry", () => {
  for (const tab of TABS.filter((t) => t.disabled)) {
    assert.equal(VIEWS[tab.id], undefined, `${tab.id}: disabled tab must not have a view — it would be reachable`);
  }
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
