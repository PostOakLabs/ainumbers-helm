// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import { blockedStateHtml, classifyBlockedState } from "./blocked-state.mjs";

test("classifyBlockedState: unavailable (404) maps to too-old", () => {
  assert.equal(classifyBlockedState({ state: "unavailable" }), "too-old");
});

test("classifyBlockedState: missing (no cache) maps to not-paired", () => {
  assert.equal(classifyBlockedState({ state: "missing" }), "not-paired");
});

test("classifyBlockedState: live/stale return null — caller renders content, not a blocked state", () => {
  assert.equal(classifyBlockedState({ state: "live" }), null);
  assert.equal(classifyBlockedState({ state: "stale" }), null);
});

test("blockedStateHtml: §13.1 never emits a bare failure sentence — heading, body and action are all present", () => {
  const html = blockedStateHtml("not-paired", { port: 4173, status: 401 });
  assert.match(html, /blocked-state-heading/);
  assert.match(html, /blocked-state-body/);
  assert.match(html, /blocked-state-action/);
});

test("blockedStateHtml: §13.3 technical details (port/status/route) are collapsed, never in the headline", () => {
  const html = blockedStateHtml("too-old", { port: 4173, status: 404, route: "/workflows" });
  const headline = html.split("<details")[0];
  assert.ok(!headline.includes("4173"));
  assert.ok(!headline.includes("404"));
  assert.match(html, /<details class="blocked-state-details">/);
  assert.match(html, /<summary>Technical details<\/summary>/);
  assert.match(html, />4173</);
  assert.match(html, />404</);
  assert.match(html, />\/workflows</);
});

test("blockedStateHtml: omits the technical-details block entirely when nothing is supplied", () => {
  const html = blockedStateHtml("not-paired", {});
  assert.ok(!html.includes("<details"));
});

test("blockedStateHtml: caller-supplied body/action override the generic copy (required for the empty case)", () => {
  const html = blockedStateHtml("empty", { body: "custom body", action: "custom action" });
  assert.match(html, /custom body/);
  assert.match(html, /custom action/);
});

test("blockedStateHtml: extra HTML (e.g. canvas's file picker, §13.5) is included", () => {
  const html = blockedStateHtml("not-paired", { extra: `<input id="import-helm-json" />` });
  assert.match(html, /id="import-helm-json"/);
});
