// Power Query bridge starter workbook (HELM-P4-B1, HELM-PHASE4-BUILD-SPEC.md
// §2 Band B row B1): a macro-free .xlsx a BA downloads once, pointed at a
// run's output-folder (see pq-export.mjs / docs/POWER-QUERY-BRIDGE.md).
//
// SCOPING DECISION (flagged for review, mirrors the A4 "builder's call"
// precedent): Excel's true "pre-built, already-loaded" Power Query state is
// stored as a binary Data Mashup package inside the .xlsx OPC container
// ([MS-QDEFF]). Hand-authoring that binary part with zero dependencies and
// no way to test against real Excel in this environment risks shipping a
// workbook Excel silently repairs or refuses to open — worse than shipping
// none. Instead this starter ships: (1) a clean, valid OOXML workbook with
// zero repair-on-open risk, (2) a ready-to-paste M query on the Setup sheet
// (one-time Data > Get Data > Launch Power Query Editor > Blank Query >
// Advanced Editor paste — not a fresh-open auto-refresh), (3) header rows on
// the data sheets matching the frozen schema field-for-field. After the
// one-time paste, Data > Refresh All works exactly as a fully pre-built
// query would. If a future session gets real Excel access to validate a
// true embedded Data Mashup part, upgrade this in place — the M script below
// is already the exact logic that part would run.
import { buildZip } from "../ui/lib/zip-writer.mjs";

const MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

function xmlEscape(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function colLetter(n) {
  let s = "";
  n += 1;
  while (n > 0) {
    const r = (n - 1) % 26;
    s = String.fromCharCode(65 + r) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function cellXml(ref, v) {
  if (typeof v === "number" && Number.isFinite(v)) return `<c r="${ref}"><v>${v}</v></c>`;
  if (v === null || v === undefined || v === "") return `<c r="${ref}"/>`;
  return `<c r="${ref}" t="inlineStr"><is><t xml:space="preserve">${xmlEscape(v)}</t></is></c>`;
}

function sheetXml(rows) {
  let body = "";
  rows.forEach((row, r) => {
    const cells = row.map((v, c) => cellXml(`${colLetter(c)}${r + 1}`, v)).join("");
    body += `<row r="${r + 1}">${cells}</row>`;
  });
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
    `<sheetData>${body}</sheetData></worksheet>`;
}

const M_QUERY = `let
    // Point this at the run's output-folder written by helmd's Power Query
    // bridge (results.json / trust-labels.json / hashes.json). LOCAL-FILE
    // mode is primary — no web/daemon-API connection required.
    RunFolder = "C:\\Path\\To\\Run\\Folder",
    ReadFile = (name as text) => Json.Document(File.Contents(RunFolder & "\\" & name)),
    Results = Table.FromRecords(ReadFile("results.json")[rows]),
    TrustLabels = Table.FromRecords(ReadFile("trust-labels.json")[rows]),
    Hashes = Table.FromRecords(ReadFile("hashes.json")[rows]),
    JoinLabels = Table.NestedJoin(Results, "digest", TrustLabels, "digest", "label_table", JoinKind.LeftOuter),
    JoinHashes = Table.NestedJoin(JoinLabels, "digest", Hashes, "digest", "hash_table", JoinKind.LeftOuter),
    ExpandLabels = Table.ExpandTableColumn(JoinHashes, "label_table", {"trust_label"}),
    ExpandHashes = Table.ExpandTableColumn(ExpandLabels, "hash_table", {"hex"})
in
    ExpandHashes`;

function readmeRows() {
  return [
    ["Helm — Power Query bridge starter workbook"],
    [],
    ["Frozen schema v1 — see docs/POWER-QUERY-BRIDGE.md for the full spec."],
    [],
    ["Setup (one time):"],
    ["1. Data > Get Data > Launch Power Query Editor"],
    ["2. New Source > Blank Query"],
    ["3. Home > Advanced Editor > paste the M script from the 'Setup' sheet"],
    ["4. Edit the RunFolder path at the top of the script to point at a run's output-folder"],
    ["5. Close & Load"],
    [],
    ["After setup: Data > Refresh All picks up the latest run's results, trust labels, and hashes."],
    [],
    ["Local-file mode is PRIMARY — reads JSON files from disk, no network call."],
    ["Optional daemon-API mode (advanced): see docs/POWER-QUERY-BRIDGE.md for the exact localhost host/port helmd binds — never any other host."],
  ];
}

function setupRows() {
  const lines = M_QUERY.split("\n");
  return [["M query — paste into Advanced Editor"], [], ...lines.map((l) => [l])];
}

function dataSheetRows(headers) {
  return [headers];
}

const SHEETS = [
  { name: "ReadMe", build: readmeRows },
  { name: "Setup", build: setupRows },
  { name: "Results", build: () => dataSheetRows(["digest", "kind", "run_id", "bundle_id"]) },
  { name: "TrustLabels", build: () => dataSheetRows(["digest", "trust_label"]) },
  { name: "Hashes", build: () => dataSheetRows(["digest", "algorithm", "hex"]) },
];

function contentTypes() {
  const overrides = SHEETS.map((_, i) =>
    `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`
  ).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
    `<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
    `<Default Extension="xml" ContentType="application/xml"/>` +
    `<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
    overrides + `</Types>`;
}

function rootRels() {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
    `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
    `</Relationships>`;
}

function workbookXml() {
  const sheets = SHEETS.map((s, i) =>
    `<sheet name="${xmlEscape(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`
  ).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
    `xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
    `<sheets>${sheets}</sheets></workbook>`;
}

function workbookRels() {
  const rels = SHEETS.map((_, i) =>
    `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`
  ).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
    `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${rels}</Relationships>`;
}

// buildPqStarterWorkbook() -> { bytes: Uint8Array, filename, media_type }
export function buildPqStarterWorkbook() {
  const files = [
    { name: "[Content_Types].xml", data: contentTypes() },
    { name: "_rels/.rels", data: rootRels() },
    { name: "xl/workbook.xml", data: workbookXml() },
    { name: "xl/_rels/workbook.xml.rels", data: workbookRels() },
    ...SHEETS.map((s, i) => ({ name: `xl/worksheets/sheet${i + 1}.xml`, data: sheetXml(s.build()) })),
  ];
  return {
    bytes: buildZip(files),
    filename: "helm-power-query-starter.xlsx",
    media_type: MEDIA_TYPE,
  };
}

export { M_QUERY };
