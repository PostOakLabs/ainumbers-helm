// Hand-rolled DER TimeStampReq (RFC 3161) encoder for the browser anchor
// client (HELM-P3-A5). This is NOT a port of hub/vendored/anchor-suite's
// tsq.mjs — that file builds the identical TLV shape via pkijs
// (hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs, ~24k lines), and
// vendoring that bundle into ui/ would violate D2 (UI ships static, no build
// step, no heavyweight deps for one small request). ../vendored/der.mjs
// already hand-rolls a DER *reader* with zero deps for the same reason; this
// is its writer counterpart, kept intentionally minimal (definite-length
// SEQUENCE/INTEGER/OID/NULL/BOOLEAN/OCTET STRING only — everything a
// TimeStampReq needs, nothing more).
//
// Field-for-field, this produces the same TimeStampReq shape
// hub/vendored/anchor-suite/lib/tsq.mjs's buildTsqDer() does (version=1,
// messageImprint{sha256, hashedMessage}, nonce, certReq=TRUE) — the shipped
// relay (anchor.ainumbers.co) and every downstream TSA accept either
// encoding equally; only the encoder differs.

const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

function derLength(n) {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  const len = derLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
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

export function derSequence(...children) {
  return tlv(0x30, concat(...children));
}

// content: a positive-integer byte string, MSB-set values get a leading
// 0x00 pad (DER INTEGER is two's-complement — an unpadded high bit reads as
// negative).
export function derInteger(bytes) {
  const needsPad = bytes.length === 0 || (bytes[0] & 0x80) !== 0;
  const content = needsPad ? concat(new Uint8Array([0x00]), bytes) : bytes;
  return tlv(0x02, content);
}

export function derOid(dotted) {
  const parts = dotted.split(".").map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    if (p === 0) {
      out.push(0);
      continue;
    }
    const chunk = [];
    let v = p;
    while (v > 0) {
      chunk.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    }
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    out.push(...chunk);
  }
  return tlv(0x06, new Uint8Array(out));
}

export function derNull() {
  return tlv(0x05, new Uint8Array(0));
}

export function derBoolean(value) {
  return tlv(0x01, new Uint8Array([value ? 0xff : 0x00]));
}

export function derOctetString(bytes) {
  return tlv(0x04, bytes);
}

export function derSet(...children) {
  return tlv(0x31, concat(...children));
}

// [n] EXPLICIT — context-specific constructed tag wrapping one child TLV
// whole (used for ContentInfo's [0] content and EncapsulatedContentInfo's
// [0] eContent, both EXPLICIT per RFC 5652/3161).
export function derExplicit(tagNumber, child) {
  return tlv(0xa0 | tagNumber, child);
}

export function derGeneralizedTime(str) {
  return tlv(0x18, new TextEncoder().encode(str));
}

// hashBytes: SHA-256 digest bytes of the value being timestamped.
// nonceBytes: random bytes (MSB cleared by the caller so the DER INTEGER
// reads positive without needing a pad byte — matches freshNonce() below).
export function buildTsqDer(hashBytes, nonceBytes) {
  const messageImprint = derSequence(
    derSequence(derOid(OID_SHA256), derNull()),
    derOctetString(hashBytes)
  );
  return derSequence(
    derInteger(new Uint8Array([1])), // version = 1
    messageImprint,
    derInteger(nonceBytes),
    derBoolean(true) // certReq
  );
}

export function freshNonce(byteLen = 8) {
  const n = new Uint8Array(byteLen);
  crypto.getRandomValues(n);
  n[0] &= 0x7f; // ensure the DER INTEGER encodes positive without a pad byte
  return n;
}

export function hexToBytes(hex) {
  const clean = hex.replace(/^sha256:/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
