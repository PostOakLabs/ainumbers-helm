import { test } from "node:test";
import assert from "node:assert/strict";

const { buildPqStarterWorkbook, M_QUERY } = await import("./pq-starter-workbook.mjs");

// Minimal local ZIP reader (STORE method only, matches buildZip's output) —
// enough to assert the .xlsx package shape without a new dependency.
function readZipEntries(bytes) {
  const entries = [];
  let i = 0;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  while (i < bytes.length && dv.getUint32(i, true) === 0x04034b50) {
    const compSize = dv.getUint32(i + 18, true);
    const nameLen = dv.getUint16(i + 26, true);
    const extraLen = dv.getUint16(i + 28, true);
    const nameStart = i + 30;
    const name = new TextDecoder().decode(bytes.slice(nameStart, nameStart + nameLen));
    const dataStart = nameStart + nameLen + extraLen;
    const data = bytes.slice(dataStart, dataStart + compSize);
    entries.push({ name, data });
    i = dataStart + compSize;
  }
  return entries;
}

test("buildPqStarterWorkbook: produces a well-formed, macro-free OOXML package", () => {
  const { bytes, filename, media_type } = buildPqStarterWorkbook();
  assert.equal(filename, "helm-power-query-starter.xlsx");
  assert.equal(media_type, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  assert.ok(bytes instanceof Uint8Array && bytes.length > 0);

  const entries = readZipEntries(bytes);
  const names = entries.map((e) => e.name);
  assert.ok(names.includes("[Content_Types].xml"));
  assert.ok(names.includes("_rels/.rels"));
  assert.ok(names.includes("xl/workbook.xml"));
  assert.ok(names.includes("xl/_rels/workbook.xml.rels"));
  for (let i = 1; i <= 5; i++) assert.ok(names.includes(`xl/worksheets/sheet${i}.xml`));

  // macro-free: no vbaProject part, no .xlsm content type, ever.
  assert.ok(!names.some((n) => n.includes("vbaProject")));
  const contentTypes = new TextDecoder().decode(entries.find((e) => e.name === "[Content_Types].xml").data);
  assert.ok(!contentTypes.includes("macroEnabled"));

  // every XML part parses (DOMParser-free well-formedness check: balanced
  // tags via a strict regex walk would be brittle — Node's XML-capable
  // util is not built in, so assert on the structural invariants that would
  // break first if generation went wrong: matching root open/close tags).
  const workbookXml = new TextDecoder().decode(entries.find((e) => e.name === "xl/workbook.xml").data);
  assert.match(workbookXml, /^<\?xml/);
  assert.match(workbookXml, /<workbook[^>]*>[\s\S]*<\/workbook>$/);
  const sheetCount = (workbookXml.match(/<sheet /g) || []).length;
  assert.equal(sheetCount, 5);

  const sheet2 = new TextDecoder().decode(entries.find((e) => e.name === "xl/worksheets/sheet2.xml").data);
  assert.ok(sheet2.includes("RunFolder"));
});

test("M_QUERY: references all three frozen-schema files and the join key", () => {
  assert.match(M_QUERY, /results\.json/);
  assert.match(M_QUERY, /trust-labels\.json/);
  assert.match(M_QUERY, /hashes\.json/);
  assert.match(M_QUERY, /"digest"/);
});
