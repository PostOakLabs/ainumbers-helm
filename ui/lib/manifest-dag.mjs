// Derives a read-only layered DAG from a workflow manifest (SPEC.md §26.3).
// The manifest schema (schema/workflow-manifest.schema.json) has no explicit
// edge list — trigger/connectors/nodes/gates/actions are flat arrays whose
// pipeline order IS the topology. This builds the layered graph that
// implies: trigger -> connectors -> compute nodes -> gates -> actions, wiring
// every item in a non-empty layer to every item in the next non-empty layer.
// Pure and DOM-free so it's unit-testable under node:test.
const LAYER_DEFS = [
  { key: "trigger", label: "Trigger" },
  { key: "connectors", label: "Connectors" },
  { key: "nodes", label: "Compute" },
  { key: "gates", label: "Gates" },
  { key: "actions", label: "Actions" },
];

function layerItems(manifest, key) {
  if (key === "trigger") return manifest.trigger ? [{ id: "trigger", ...manifest.trigger }] : [];
  const idField = { connectors: "connector_id", nodes: "node_id", gates: "gate_id", actions: "action_id" }[key];
  return (manifest[key] ?? []).map((item) => ({ id: item[idField], ...item }));
}

export function buildDag(manifest) {
  const layers = LAYER_DEFS.map((def) => ({ ...def, items: layerItems(manifest, def.key) })).filter(
    (l) => l.items.length > 0
  );

  const edges = [];
  for (let i = 0; i < layers.length - 1; i++) {
    for (const from of layers[i].items) {
      for (const to of layers[i + 1].items) {
        edges.push({ from: `${layers[i].key}:${from.id}`, to: `${layers[i + 1].key}:${to.id}` });
      }
    }
  }
  return { layers, edges };
}
