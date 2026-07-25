// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import { esc } from "./esc.mjs";

test("esc: escapes all 5 HTML-significant characters", () => {
  assert.equal(esc(`&<>"'`), "&amp;&lt;&gt;&quot;&#39;");
});

test("esc: attribute-breakout string is fully neutralized", () => {
  const hostile = `x" onmouseover="alert(1)`;
  const escaped = esc(hostile);
  assert.ok(!escaped.includes('"'));
  assert.equal(escaped, "x&quot; onmouseover=&quot;alert(1)");
});

test("esc: script-tag breakout string is fully neutralized", () => {
  const hostile = `</pre><script>alert(1)</script>`;
  const escaped = esc(hostile);
  assert.ok(!escaped.includes("<"));
  assert.ok(!escaped.includes(">"));
});

test("esc: null/undefined coerce to empty string, not the literal words", () => {
  assert.equal(esc(null), "");
  assert.equal(esc(undefined), "");
});

test("esc: non-string input is stringified before escaping", () => {
  assert.equal(esc(42), "42");
});
