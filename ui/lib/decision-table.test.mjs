import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { renderKernelDecisionTableHtml, buildKernelDecisionTableDmn } from "./decision-table.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(HERE, "..", "..", "hub", "vendored", "ocg", "kernels", "fixtures");

const CARD = {
  kernel_id: "art-001",
  tool_version: "1.0.0",
  display_name: "Example Kernel",
  description: "Computes <stuff>.",
  source_url: "https://ainumbers.co/chaingraph/art-001.html",
  kernel_digest: "sha256:" + "a".repeat(64),
  conformance_fixtures_vendored: true,
  test_vectors: [
    { name: "case-1", policy_parameters: { x: 1, nested: { a: "hi" } }, expected_output_payload: { y: 2, ok: true }, expected_execution_hash: "deadbeef" },
    { name: "case-2 <b>", policy_parameters: { x: 5 }, expected_output_payload: { y: 10, ok: false, extra: "z" }, expected_execution_hash: "cafef00d" },
  ],
  generated_at: "2026-07-24T00:00:00.000Z",
};

test("renderKernelDecisionTableHtml: one row per test vector, columns for every input/output leaf", () => {
  const html = renderKernelDecisionTableHtml(CARD);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /case-1/);
  assert.match(html, /case-2 &lt;b&gt;/);
  assert.doesNotMatch(html, /case-2 <b>/);
  assert.match(html, /nested\.a/); // flattened nested input leaf
  assert.match(html, /extra/); // output column present only on vector 2
  assert.match(html, /Read-only/);
});

test("buildKernelDecisionTableDmn: well-formed DMN 1.5 XML, one rule per test vector", () => {
  const xml = buildKernelDecisionTableDmn(CARD);
  assert.match(xml, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.match(xml, /<definitions[^>]*xmlns="https:\/\/www\.omg\.org\/spec\/DMN\/20230324\/MODEL\/"[^>]*>[\s\S]*<\/definitions>\s*$/);
  assert.match(xml, /<decisionTable[^>]*hitPolicy="COLLECT"[^>]*>/);

  const openTags = (tag) => (xml.match(new RegExp(`<${tag}[ >]`, "g")) ?? []).length;
  const closeTags = (tag) => (xml.match(new RegExp(`</${tag}>`, "g")) ?? []).length;
  const selfClosed = (tag) => (xml.match(new RegExp(`<${tag}[^>]*/>`, "g")) ?? []).length;
  // <output> is self-closing (no leaf content); the rest pair open/close tags.
  assert.equal(openTags("output"), selfClosed("output"), "output elements must be self-closed");
  for (const tag of ["definitions", "decision", "decisionTable", "input", "rule", "inputEntry", "outputEntry"]) {
    assert.equal(openTags(tag), closeTags(tag), `${tag} open/close tag count must balance`);
  }

  const ruleCount = (xml.match(/<rule /g) ?? []).length;
  assert.equal(ruleCount, CARD.test_vectors.length);

  // no unescaped angle brackets from kernel names leaking into attribute text
  assert.doesNotMatch(xml, /name="Example Kernel"[^>]*<b>/);
});

test("renders for >=5 real vendored kernels without throwing", () => {
  const files = readdirSync(FIXTURES_DIR).filter((f) => f.endsWith(".fixtures.json")).slice(0, 5);
  assert.ok(files.length >= 5, "expected at least 5 vendored fixture files to exist");
  for (const file of files) {
    const fixtures = JSON.parse(readFileSync(join(FIXTURES_DIR, file), "utf8"));
    const card = {
      kernel_id: file.replace(/\.fixtures\.json$/, ""),
      display_name: file,
      kernel_digest: "sha256:" + "a".repeat(64),
      generated_at: "2026-07-24T00:00:00.000Z",
      test_vectors: (fixtures.vectors ?? []).map((v) => ({
        name: v.name,
        policy_parameters: v.policy_parameters,
        expected_output_payload: v.output_payload,
        expected_execution_hash: v.golden_hash,
      })),
    };
    assert.doesNotThrow(() => renderKernelDecisionTableHtml(card));
    assert.doesNotThrow(() => buildKernelDecisionTableDmn(card));
  }
});
