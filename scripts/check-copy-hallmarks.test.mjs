// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Coverage for check-copy-hallmarks.mjs (HELM-COPY-GATE-1). The false-positive
// direction (a tell inside fenced/inline code failing the gate) is what gets a
// gate disabled — those negative tests come first and outnumber the positives.
import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeFile, prose } from "./check-copy-hallmarks.mjs";

// --- Negative: fenced/inline code must never trip the gate ---

test("fenced code block containing an em-dash does not fail", () => {
  const md = "Some prose.\n\n```js\nconst x = 1; // em-dash inside a fence — must not count\n```\n\nMore prose.";
  assert.equal(analyzeFile(md), null);
});

test("fenced code block containing an ANTI-AI-TELL phrase does not fail", () => {
  const md = "```\nThis is not just a test. It is a fixture.\n```\n";
  assert.equal(analyzeFile(md), null);
});

test("inline backtick span containing an em-dash does not fail", () => {
  const md = "Use the `--flag—value` option.";
  assert.equal(analyzeFile(md), null);
});

test("inline double-backtick span containing a literal backtick does not fail and does not leak into prose", () => {
  const md = "The token is ``a`b`` in this doc.";
  assert.equal(analyzeFile(md), null);
});

test("fenced code with a tilde fence is stripped too", () => {
  const md = "~~~\nnot just a placeholder — real code\n~~~\n";
  assert.equal(analyzeFile(md), null);
});

test("URL inside a markdown link is never matched, only the link text", () => {
  // "delve" only appears in the URL, never in the visible text.
  const md = "See the [docs](https://example.com/delve-deeper) for more.";
  assert.equal(analyzeFile(md), null);
});

test("HTML comment content is not prose", () => {
  const md = "<!-- not just a note — internal only -->\n\nReal prose here.";
  assert.equal(analyzeFile(md), null);
});

test("frontmatter is not prose", () => {
  const md = "---\ntitle: not just a title — a test\n---\n\nBody text.";
  assert.equal(analyzeFile(md), null);
});

test("reference-link definition line is not prose", () => {
  const md = "See [the guide][ref].\n\n[ref]: https://example.com \"not just a link — a definition\"";
  assert.equal(analyzeFile(md), null);
});

test("legitimate bold-labeled line (markdown structure) does not trip the heading-styling check", () => {
  const md = "**Repo:** `PostOakLabs/ainumbers-helm`, branch `main`.";
  assert.equal(analyzeFile(md), null);
});

test("a heading containing an inline bold term is not flagged (only a fully-styled heading is)", () => {
  const md = "## The **Vault** subsystem\n\nProse.";
  assert.equal(analyzeFile(md), null);
});

// --- Positive: real prose tells must fail ---

test("em-dash in real prose is counted", () => {
  const md = "This is prose — with an em-dash in it.";
  const f = analyzeFile(md);
  assert.equal(f.emdash, 1);
});

test("a fully bold-styled heading is flagged", () => {
  const md = "## **The Big Reveal**\n\nProse.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("bold/italic-styled heading")));
});

test('"not just X but Y" in prose is flagged', () => {
  const md = "This tool is not just a calculator but a full ledger.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("not just X but")));
});

test('dramatic-fragment opener "The result?" is flagged', () => {
  const md = "We tuned the gate. The result? Zero false positives.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("dramatic-fragment")));
});

test('two-tone comma pivot is flagged', () => {
  const md = "It's not a workaround, it's the design.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("it's not X, it's Y")));
});

test("filler-vocab hit is flagged", () => {
  const md = "This document will delve into the details.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes('filler-vocab "delve"')));
});

test("elevate is narrowed to the marketing collocation — domain sense is clean", () => {
  const md = "This flag triggers elevated risk review under the policy.";
  assert.equal(analyzeFile(md), null);
});

test("elevate marketing collocation is flagged", () => {
  const md = "Elevate your workflow with this tool.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("elevate your/our/its X")));
});

test("unlock is narrowed to the marketing sense — literal UI-mechanic sense is clean", () => {
  const md = "Stage 3 unlocks after the vault is provisioned.";
  assert.equal(analyzeFile(md), null);
});

test("unlock marketing sense is flagged", () => {
  const md = "Unlock your potential with this feature.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("unlock potential/value/growth")));
});

test("decorative emoji in a heading is flagged", () => {
  const md = "## 🚀 Getting Started\n\nProse.";
  const f = analyzeFile(md);
  assert.ok(f.hallmarks.some((h) => h.includes("emoji-in-heading")));
});

test("UI-exempt status emoji in a heading is not flagged", () => {
  const md = "## ✅ Setup Complete\n\nProse.";
  assert.equal(analyzeFile(md), null);
});

test("overuse count is tracked per file (cap enforcement happens in main(), against baseline/OVERUSE_CAP)", () => {
  const one = "We were honest about the tradeoff.";
  assert.equal(analyzeFile(one).overuse.honest, 1);
  const two = "We were honest about the tradeoff. Honestly, it mattered.";
  assert.equal(analyzeFile(two).overuse.honest, 2);
});

// --- prose() extraction unit checks ---

test("prose() strips a fenced block entirely", () => {
  const md = "before\n```\ncode — here\n```\nafter";
  const p = prose(md);
  assert.ok(!p.includes("—"));
  assert.ok(p.includes("before"));
  assert.ok(p.includes("after"));
});
