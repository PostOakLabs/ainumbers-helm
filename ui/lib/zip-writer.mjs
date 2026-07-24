// Minimal STORE-method (uncompressed) ZIP writer — HELM-P3-V9's bundle.zip
// export needs no compression (its payload is already-tiny HTML/JSON), and a
// hand-rolled STORE writer keeps the export dependency-free (D2) rather than
// pulling in a general-purpose zip library for one deflate feature nothing
// here uses. Pure Uint8Array in/out — runs in Node and the browser alike.
// Format: PKZIP local file headers + central directory + EOCD, no zip64
// (bundle exports are small; if that ever changes, extend rather than
// silently truncate).

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

function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  return new TextEncoder().encode(data);
}

// DOS date/time fixed at the epoch (1980-01-01 00:00:00) — bundle exports are
// content-addressed by hash, not by wall-clock mtime, so a stable placeholder
// keeps re-exporting the same bundle byte-identical.
const DOS_TIME = 0;
const DOS_DATE = 0x21;

function u16(n) {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
}
function u32(n) {
  return new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}
function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// files: [{ name, data: Uint8Array|string }]. Returns a Uint8Array — the
// complete .zip archive.
export function buildZip(files) {
  const nameBytes = files.map((f) => new TextEncoder().encode(f.name));
  const dataBytes = files.map((f) => toBytes(f.data));
  const crcs = dataBytes.map(crc32);
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (let i = 0; i < files.length; i++) {
    const name = nameBytes[i];
    const data = dataBytes[i];
    const crc = crcs[i];
    const localHeader = concat(
      u32(0x04034b50), u16(20), u16(0), u16(0), // version needed, flags, method (0 = store)
      u16(DOS_TIME), u16(DOS_DATE),
      u32(crc), u32(data.length), u32(data.length),
      u16(name.length), u16(0), name
    );
    localParts.push(localHeader, data);

    const centralHeader = concat(
      u32(0x02014b50), u16(20), u16(20), u16(0), u16(0),
      u16(DOS_TIME), u16(DOS_DATE),
      u32(crc), u32(data.length), u32(data.length),
      u16(name.length), u16(0), u16(0), u16(0), u16(0), u32(0),
      u32(offset), name
    );
    centralParts.push(centralHeader);
    offset += localHeader.length + data.length;
  }

  const central = concat(...centralParts);
  const eocd = concat(
    u32(0x06054b50), u16(0), u16(0),
    u16(files.length), u16(files.length),
    u32(central.length), u32(offset), u16(0)
  );

  return concat(...localParts, central, eocd);
}
