import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildDag } from "./manifest-dag.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const golden = JSON.parse(readFileSync(join(ROOT, "fixtures", "workflow-manifest", "golden.json"), "utf8"));

test("buildDag layers golden fixture as trigger -> connectors -> nodes -> gates -> actions", () => {
  const { layers } = buildDag(golden);
  assert.deepEqual(layers.map((l) => l.key), ["trigger", "connectors", "nodes", "gates", "actions"]);
  assert.equal(layers.find((l) => l.key === "nodes").items[0].id, "n1");
});

test("buildDag skips empty layers", () => {
  const { layers } = buildDag({ ...golden, gates: [], actions: [] });
  assert.deepEqual(layers.map((l) => l.key), ["trigger", "connectors", "nodes"]);
});

test("buildDag connects every item in a layer to every item in the next", () => {
  const manifest = {
    ...golden,
    connectors: [
      { connector_id: "c1", contract_digest: golden.connectors[0].contract_digest },
      { connector_id: "c2", contract_digest: golden.connectors[0].contract_digest },
    ],
    nodes: [
      { node_id: "n1", kernel_id: "k1", kernel_digest: golden.nodes[0].kernel_digest },
      { node_id: "n2", kernel_id: "k2", kernel_digest: golden.nodes[0].kernel_digest },
    ],
  };
  const { edges } = buildDag(manifest);
  const connectorToNode = edges.filter((e) => e.from.startsWith("connectors:") && e.to.startsWith("nodes:"));
  assert.equal(connectorToNode.length, 4);
});

test("buildDag on a manifest with only a trigger produces no edges", () => {
  const { layers, edges } = buildDag({ ...golden, connectors: [], nodes: [], gates: [], actions: [] });
  assert.equal(layers.length, 1);
  assert.equal(edges.length, 0);
});
