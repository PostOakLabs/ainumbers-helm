import { test } from "node:test";
import assert from "node:assert/strict";
import { renderEucEntryHtml, renderKernelCardHtml } from "./euc-html.mjs";

const ENTRY = {
  workflow_id: "pack-example",
  name: "Example Workflow",
  owner: "A & B Compliance",
  purpose: null,
  control_description: "<script>alert(1)</script>",
  last_validated: "2026-07-01",
  kernels: [{ node_id: "n1", kernel_id: "art-001", kernel_digest: "sha256:" + "a".repeat(64) }],
  declared_inputs: [],
  declared_outputs: [{ node_id: "n1", kernel_id: "art-001", note: "terminal" }],
  workflow_manifest_digest: "sha256:" + "b".repeat(64),
  generated_at: "2026-07-23T00:00:00.000Z",
};

const CARD = {
  kernel_id: "art-001",
  tool_version: "1.0.0",
  display_name: "Example Kernel",
  description: "Computes <stuff>.",
  source_url: "https://ainumbers.co/chaingraph/art-001.html",
  kernel_digest: "sha256:" + "a".repeat(64),
  conformance_fixtures_vendored: true,
  test_vectors: [{ name: "case-1", policy_parameters: { x: 1 }, expected_output_payload: { y: 2 }, expected_execution_hash: "deadbeef" }],
  replay_instructions: "Do the thing.",
  generated_at: "2026-07-23T00:00:00.000Z",
};

test("renderEucEntryHtml: produces a self-contained HTML document with the entry's data", () => {
  const html = renderEucEntryHtml(ENTRY);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Example Workflow/);
  assert.match(html, /art-001/);
  assert.match(html, /2026-07-01/);
});

test("renderEucEntryHtml: escapes HTML-unsafe content instead of injecting it raw", () => {
  const html = renderEucEntryHtml(ENTRY);
  assert.doesNotMatch(html, /<script>alert/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /A &amp; B Compliance/);
});

test("renderKernelCardHtml: produces a self-contained HTML document with test vectors", () => {
  const html = renderKernelCardHtml(CARD);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Example Kernel/);
  assert.match(html, /case-1/);
  assert.match(html, /deadbeef/);
  assert.doesNotMatch(html, /<stuff>/);
});
