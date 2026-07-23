import test from "node:test";
import assert from "node:assert/strict";
import { toYaml } from "./to-yaml.mjs";

test("toYaml renders scalars", () => {
  assert.equal(toYaml("hello"), "hello\n");
  assert.equal(toYaml(1), "1\n");
  assert.equal(toYaml(null), "null\n");
});

test("toYaml renders a flat object", () => {
  assert.equal(toYaml({ a: 1, b: "x" }), "a: 1\nb: x\n");
});

test("toYaml renders an empty array as []", () => {
  assert.equal(toYaml({ items: [] }), "items: []\n");
});

test("toYaml renders an array of objects with dash prefix", () => {
  const out = toYaml({ nodes: [{ node_id: "n1", kernel_id: "k1" }] });
  assert.ok(out.includes("nodes:\n"));
  assert.ok(out.includes("- node_id: n1"));
  assert.ok(out.includes("kernel_id: k1"));
});

test("toYaml quotes strings needing escape", () => {
  const out = toYaml({ schedule: "0 6 * * *" });
  assert.ok(out.startsWith("schedule: 0 6 * * *"));
});
