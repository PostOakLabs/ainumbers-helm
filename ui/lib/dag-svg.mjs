// Renders a buildDag() graph to an SVG string. Pure string-in/string-out —
// no DOM globals — so layout math is unit-testable under node:test.
const COL_W = 220;
const ROW_H = 64;
const NODE_W = 176;
const NODE_H = 40;
const PAD = 32;

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function nodeCenter(colIndex, rowIndex) {
  return { x: PAD + colIndex * COL_W + NODE_W / 2, y: PAD + rowIndex * ROW_H + NODE_H / 2 };
}

export function layoutDag({ layers, edges }) {
  const positions = new Map();
  layers.forEach((layer, colIndex) => {
    layer.items.forEach((item, rowIndex) => {
      positions.set(`${layer.key}:${item.id}`, { ...nodeCenter(colIndex, rowIndex), layer: layer.key, item });
    });
  });
  const maxRows = Math.max(1, ...layers.map((l) => l.items.length));
  const width = PAD * 2 + Math.max(1, layers.length) * COL_W;
  const height = PAD * 2 + maxRows * ROW_H;
  return { positions, width, height, edges };
}

function itemLabel(layerKey, item) {
  if (layerKey === "trigger") return item.type ?? "trigger";
  if (layerKey === "connectors") return item.connector_id;
  if (layerKey === "nodes") return item.kernel_id;
  if (layerKey === "gates") return `${item.gate_id}: ${item.type}`;
  if (layerKey === "actions") return `${item.type} → ${item.target_host}`;
  return item.id;
}

export function renderDagSvg(dag) {
  const { positions, width, height, edges } = layoutDag(dag);

  const edgeSvg = edges
    .map((e) => {
      const a = positions.get(e.from);
      const b = positions.get(e.to);
      if (!a || !b) return "";
      const x1 = a.x + NODE_W / 2, x2 = b.x - NODE_W / 2;
      const midX = (x1 + x2) / 2;
      return `<path d="M ${x1} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${x2} ${b.y}" class="dag-edge" fill="none" marker-end="url(#dag-arrow)" />`;
    })
    .join("");

  const nodeSvg = Array.from(positions.entries())
    .map(([id, pos]) => {
      const label = esc(itemLabel(pos.layer, pos.item));
      return `<g class="dag-node" data-layer="${pos.layer}" role="listitem" aria-label="${label}">
        <rect x="${pos.x - NODE_W / 2}" y="${pos.y - NODE_H / 2}" width="${NODE_W}" height="${NODE_H}" rx="6" />
        <text x="${pos.x}" y="${pos.y}" text-anchor="middle" dominant-baseline="middle">${label}</text>
      </g>`;
    })
    .join("");

  const colLabelSvg = dag.layers
    .map(
      (layer, i) =>
        `<text x="${PAD + i * COL_W + NODE_W / 2}" y="${PAD - 12}" text-anchor="middle" class="dag-col-label">${esc(layer.label)}</text>`
    )
    .join("");

  return `<svg viewBox="0 0 ${width} ${height + 16}" role="img" aria-label="Workflow manifest graph (read-only)" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <marker id="dag-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M 0 0 L 10 5 L 0 10 z" class="dag-arrowhead" />
      </marker>
    </defs>
    ${colLabelSvg}
    ${edgeSvg}
    ${nodeSvg}
  </svg>`;
}
