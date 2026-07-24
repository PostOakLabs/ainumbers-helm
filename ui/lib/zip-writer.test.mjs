// HELM-P3-V9's bundle.zip writer — proves buildZip() output is a structurally
// valid, standard STORE-method ZIP (a real unzip tool, not just our own
// code, must be able to read it) by re-implementing a minimal ZIP *reader*
// independently (central directory + local headers, CRC32 check) rather than
// round-tripping through buildZip's own internals.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildZip } from "./zip-writer.mjs";

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
function crc32(bytes) {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function readZip(zip) {
  const dv = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  // Find EOCD by scanning back for its 4-byte signature (no comment field used here).
  let eocdOff = -1;
  for (let i = zip.length - 22; i >= 0; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocdOff = i; break; }
  }
  assert.notEqual(eocdOff, -1, "EOCD signature not found");
  const count = dv.getUint16(eocdOff + 10, true);
  const centralOffset = dv.getUint32(eocdOff + 16, true);

  const entries = [];
  let off = centralOffset;
  for (let i = 0; i < count; i++) {
    assert.equal(dv.getUint32(off, true), 0x02014b50, "central directory signature mismatch");
    const crc = dv.getUint32(off + 16, true);
    const compSize = dv.getUint32(off + 20, true);
    const nameLen = dv.getUint16(off + 28, true);
    const localHeaderOffset = dv.getUint32(off + 42, true);
    const name = new TextDecoder().decode(zip.subarray(off + 46, off + 46 + nameLen));
    off += 46 + nameLen;

    assert.equal(dv.getUint32(localHeaderOffset, true), 0x04034b50, "local header signature mismatch");
    const localNameLen = dv.getUint16(localHeaderOffset + 26, true);
    const dataStart = localHeaderOffset + 30 + localNameLen;
    const data = zip.subarray(dataStart, dataStart + compSize);
    assert.equal(crc32(data), crc, `CRC32 mismatch for ${name}`);
    entries.push({ name, data });
  }
  return entries;
}

test("buildZip: round-trips multiple files, readable by an independent reader", () => {
  const files = [
    { name: "bundle.json", data: JSON.stringify({ a: 1 }) },
    { name: "verify.html", data: "<html><body>hi</body></html>" },
    { name: "binary.bin", data: new Uint8Array([0, 1, 2, 255, 254, 253]) },
  ];
  const zip = buildZip(files);
  const entries = readZip(zip);
  assert.equal(entries.length, 3);
  assert.equal(new TextDecoder().decode(entries[0].data), files[0].data);
  assert.equal(new TextDecoder().decode(entries[1].data), files[1].data);
  assert.deepEqual([...entries[2].data], [0, 1, 2, 255, 254, 253]);
  assert.deepEqual(entries.map((e) => e.name), files.map((f) => f.name));
});

test("buildZip: empty file list produces a valid (empty) archive", () => {
  const zip = buildZip([]);
  assert.deepEqual(readZip(zip), []);
});
