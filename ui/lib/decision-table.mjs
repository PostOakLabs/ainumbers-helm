// Kernel decision-table cards (HELM-P4-A4, HELM-PHASE4-BUILD-SPEC.md §2 Band A
// row A4). Reshapes a kernel validation card's test vectors (already the
// input->output ground truth committed as fixtures, see hub/euc-register.mjs)
// into a committee-legible, read-only decision table: one column per input/
// output field, one row per test vector. Hand-rolled render chosen over
// dmn-js (builder's call per the row) — helm ships zero runtime deps today
// (package.json has no "dependencies") and a template-string table matches
// the existing precedent (ui/lib/euc-html.mjs, hub/pq-starter-workbook.mjs);
// pulling in dmn-js's mandatory-watermark bundle for a table Helm can already
// hand-roll would be the first dependency added for no behavioral gain.
// Same "no DOM globals" discipline as euc-html.mjs — pure template functions,
// unit-testable under node:test.

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Flattens a (possibly nested) object into ordered [dotPath, value] leaf
// pairs. Arrays and primitives are leaves as-is; this is a documentation
// reshape of already-computed fixture data, not a schema — no cycle guard
// needed (fixture JSON is finite, committed, and never kernel-live).
function flattenLeaves(obj, prefix = "") {
  const out = [];
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      out.push(...flattenLeaves(v, prefix ? `${prefix}.${k}` : k));
    }
  } else {
    out.push([prefix, obj]);
  }
  return out;
}

// Union of leaf-path columns across all vectors, in first-seen order — a
// column present in only some vectors still gets a header, empty cells
// elsewhere (a kernel with conditional/optional output fields, e.g. the ACA
// safe-harbor kernel's per-harbor branches, is exactly why this matters).
function collectColumns(vectors, pick) {
  const columns = [];
  const seen = new Set();
  for (const v of vectors) {
    for (const [path] of flattenLeaves(pick(v))) {
      if (!seen.has(path)) {
        seen.add(path);
        columns.push(path);
      }
    }
  }
  return columns;
}

function cellText(value) {
  if (value === undefined) return "";
  if (value === null) return "null";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function leafMap(obj) {
  return new Map(flattenLeaves(obj));
}

export function renderKernelDecisionTableHtml(card) {
  const vectors = card.test_vectors ?? [];
  const inputCols = collectColumns(vectors, (v) => v.policy_parameters ?? {});
  const outputCols = collectColumns(vectors, (v) => v.expected_output_payload ?? {});

  const headerGroup = `<tr><th>Case</th><th colspan="${inputCols.length || 1}">Inputs</th><th colspan="${outputCols.length || 1}">Outputs</th></tr>`;
  const headerCols = `<tr><th></th>${inputCols.map((c) => `<th>${esc(c)}</th>`).join("") || "<th>&mdash;</th>"}${outputCols
    .map((c) => `<th>${esc(c)}</th>`)
    .join("") || "<th>&mdash;</th>"}</tr>`;

  const rows = vectors
    .map((v) => {
      const inMap = leafMap(v.policy_parameters ?? {});
      const outMap = leafMap(v.expected_output_payload ?? {});
      const inCells = (inputCols.length ? inputCols : [""]).map((c) => `<td>${esc(cellText(inMap.get(c)))}</td>`).join("");
      const outCells = (outputCols.length ? outputCols : [""]).map((c) => `<td>${esc(cellText(outMap.get(c)))}</td>`).join("");
      return `<tr><td>${esc(v.name)}</td>${inCells}${outCells}</tr>`;
    })
    .join("");

  const body = `
<h1>Kernel decision table</h1>
<p class="meta">${esc(card.kernel_id)} &mdash; generated ${esc(card.generated_at)}</p>
<table class="decision-table">
  ${headerGroup}
  ${headerCols}
  ${rows}
</table>
<p class="meta">Read-only, derived from ${vectors.length} committed test vector${vectors.length === 1 ? "" : "s"} (version hash <code>${esc(
    card.kernel_digest
  )}</code>) &mdash; not an editable rule set.</p>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${esc(`Decision table — ${card.display_name}`)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 64rem; margin: 2rem auto; padding: 0 1rem; color: #111; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  table.decision-table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; }
  table.decision-table th, table.decision-table td { text-align: left; padding: 0.35rem 0.5rem; border: 1px solid #ddd; font-size: 0.85rem; vertical-align: top; }
  table.decision-table th { background: #f4f4f4; }
  code { font-family: ui-monospace, monospace; font-size: 0.8rem; }
  .meta { color: #555; font-size: 0.85rem; }
  @media print { body { margin: 0; max-width: none; } }
</style>
</head>
<body>
${body}
</body>
</html>`;
}

// FEEL literal encoding for a fixture value: quoted string, bare number/
// boolean, "null" literal, or a JSON-stringified-then-quoted fallback for
// objects/arrays (DMN's XML schema only requires <text> be a string; it
// does not validate FEEL grammar, so this stays a best-effort documentation
// literal, not a parsed expression).
function feelLiteral(value) {
  if (value === undefined || value === null) return "null";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (typeof value === "object") return JSON.stringify(JSON.stringify(value));
  return JSON.stringify(String(value));
}

function slugId(s) {
  return String(s).replace(/[^a-zA-Z0-9_]/g, "_");
}

// DMN 1.5 XML export of the same cards (rider on HELM-P4-A4). One <decision>
// with a single <decisionTable>: an input column per policy_parameters leaf,
// an output column per expected_output_payload leaf, one <rule> per test
// vector. hitPolicy COLLECT — this documents observed input/output pairs,
// it is not an exclusive-match rule set (MISMO/banking interchange target
// only needs well-formed, schema-shaped DMN, not editable business logic).
export function buildKernelDecisionTableDmn(card) {
  const vectors = card.test_vectors ?? [];
  const inputCols = collectColumns(vectors, (v) => v.policy_parameters ?? {});
  const outputCols = collectColumns(vectors, (v) => v.expected_output_payload ?? {});
  const decisionId = `decision_${slugId(card.kernel_id)}`;
  const tableId = `decisionTable_${slugId(card.kernel_id)}`;

  const inputs = (inputCols.length ? inputCols : ["input_1"])
    .map(
      (c, i) => `      <input id="input_${i + 1}" label="${esc(c)}">
        <inputExpression id="inputExpression_${i + 1}" typeRef="string"><text>${esc(c)}</text></inputExpression>
      </input>`
    )
    .join("\n");

  const outputs = (outputCols.length ? outputCols : ["output_1"])
    .map((c, i) => `      <output id="output_${i + 1}" label="${esc(c)}" name="${esc(c)}" typeRef="string" />`)
    .join("\n");

  const rules = vectors
    .map((v, ri) => {
      const inMap = leafMap(v.policy_parameters ?? {});
      const outMap = leafMap(v.expected_output_payload ?? {});
      const inEntries = (inputCols.length ? inputCols : [""])
        .map((c, i) => `        <inputEntry id="inputEntry_${ri + 1}_${i + 1}"><text>${esc(feelLiteral(inMap.get(c)))}</text></inputEntry>`)
        .join("\n");
      const outEntries = (outputCols.length ? outputCols : [""])
        .map((c, i) => `        <outputEntry id="outputEntry_${ri + 1}_${i + 1}"><text>${esc(feelLiteral(outMap.get(c)))}</text></outputEntry>`)
        .join("\n");
      return `      <rule id="rule_${ri + 1}">
        <!-- ${esc(v.name)} -->
${inEntries}
${outEntries}
      </rule>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="https://www.omg.org/spec/DMN/20230324/MODEL/" id="definitions_${slugId(card.kernel_id)}" name="${esc(
    card.display_name
  )}" namespace="https://ainumbers.co/helm/dmn/${esc(card.kernel_id)}">
  <decision id="${decisionId}" name="${esc(card.display_name)}">
    <decisionTable id="${tableId}" hitPolicy="COLLECT">
${inputs}
${outputs}
${rules}
    </decisionTable>
  </decision>
</definitions>
`;
}
