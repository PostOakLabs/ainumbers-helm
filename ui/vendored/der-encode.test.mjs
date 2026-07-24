import { test } from "node:test";
import assert from "node:assert/strict";
import { derOid, derInteger, derSequence, buildTsqDer, freshNonce, hexToBytes, bytesToBase64 } from "./der-encode.mjs";
import { parseRfc3161MessageImprint } from "./der.mjs";

function hex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

test("derOid encodes the well-known SHA-256 OID to its standard DER bytes", () => {
  // 2.16.840.1.101.3.4.2.1 — RFC 3874 / widely published test vector.
  assert.equal(hex(derOid("2.16.840.1.101.3.4.2.1")), "0609608648016503040201");
});

test("derInteger pads a value whose MSB is set so it reads positive", () => {
  assert.equal(hex(derInteger(new Uint8Array([0x80]))), "02020080");
  assert.equal(hex(derInteger(new Uint8Array([0x01]))), "020101");
});

test("derSequence sums child lengths into its own definite-length header", () => {
  const seq = derSequence(derInteger(new Uint8Array([1])), derInteger(new Uint8Array([2])));
  // tag 0x30, length 6 (two 3-byte INTEGER TLVs), then the two children verbatim.
  assert.equal(hex(seq), "3006" + "020101" + "020102");
});

test("buildTsqDer nests a well-formed SEQUENCE whose outer length matches its body", () => {
  const hash = hexToBytes("af2c0d0db5baec3e06592c51e073a7606955a005fe70bbbce5c0f85c08fe2f0b");
  const der = buildTsqDer(hash, freshNonce());
  assert.equal(der[0], 0x30); // outer SEQUENCE tag
  // Definite short-form or long-form length must account for exactly the
  // remaining bytes — reject silently-truncated or over-long encodings.
  let lenByte = der[1];
  let bodyStart = 2;
  let bodyLen;
  if (lenByte & 0x80) {
    const n = lenByte & 0x7f;
    bodyLen = 0;
    for (let i = 0; i < n; i++) bodyLen = bodyLen * 256 + der[2 + i];
    bodyStart = 2 + n;
  } else {
    bodyLen = lenByte;
  }
  assert.equal(der.length, bodyStart + bodyLen);
});

test("buildTsqDer output base64-encodes to a well-formed string", () => {
  const hashHex = "af2c0d0db5baec3e06592c51e073a7606955a005fe70bbbce5c0f85c08fe2f0b";
  const der = buildTsqDer(hexToBytes(hashHex), freshNonce());
  const b64 = bytesToBase64(der);
  assert.match(b64, /^[A-Za-z0-9+/]+=*$/);
});
