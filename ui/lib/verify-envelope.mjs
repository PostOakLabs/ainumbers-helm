// Browser-side DSSE/in-toto envelope verifier (HELM-U3, mirrors hub/envelope.mjs
// verifyEnvelope() for the daemon-free Verify view). Ed25519 via WebCrypto
// (same importKey('jwk', {kty:'OKP',crv:'Ed25519',...}) pattern already shipped
// in the site's art-424-witness-cosignature-verifier.kernel.mjs verifyEd25519());
// ML-DSA-44 via the vendored pure-JS noble impl (../vendored/proof.mjs) since
// WebCrypto has no PQC primitive. Same DSSE PAE + JCS canonicalization as the
// hub copy, so a Node-signed envelope verifies byte-for-byte identically here.
import { cgCanon, assertIJson } from "../vendored/hash.mjs";
import { ml_dsa44 } from "../vendored/proof.mjs";

const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const enc = new TextEncoder();

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function pae(payloadType, payloadBytes) {
  return concatBytes(
    enc.encode("DSSEv1"), enc.encode(" "),
    enc.encode(String(enc.encode(payloadType).length)), enc.encode(" "), enc.encode(payloadType), enc.encode(" "),
    enc.encode(String(payloadBytes.length)), enc.encode(" "), payloadBytes
  );
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function base64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// publicKeys: { ed25519SpkiB64: string (SPKI DER, base64), mldsa44B64: string|null (raw pubkey, base64) }
// — the shape a Helm operator hands out alongside a bundle for offline verify
// (see ../views/verify.mjs's "producer identity" input; Helm has no key
// registry by design, D1).
async function importEd25519(spkiB64) {
  const der = base64ToBytes(spkiB64);
  // SPKI wraps a 32-byte raw Ed25519 key at a fixed tail offset; WebCrypto's
  // 'raw' import for OKP expects that raw key directly.
  const raw = der.slice(der.length - 32);
  const jwk = { kty: "OKP", crv: "Ed25519", x: base64urlEncode(raw) };
  return globalThis.crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
}

// Mirrors hub/envelope.mjs verifyEnvelope(): Ed25519 is MUST (its absence or
// failure always fails the envelope), ML-DSA-44 is SHOULD (absent doesn't fail,
// present-and-wrong does, so a tampered PQC co-signature is still caught).
export async function verifyEnvelope(envelope, publicKeys) {
  if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) {
    return { valid: false, ed25519: false, mldsa44: null, statement: null };
  }
  const payloadBytes = base64ToBytes(envelope.payload);
  const toVerify = pae(envelope.payloadType, payloadBytes);

  const edEntry = envelope.signatures.find((s) => s.alg === "EdDSA" || s.alg === "Ed25519");
  const mldsaEntry = envelope.signatures.find((s) => s.alg === "ML-DSA-44");

  let ed25519 = false;
  if (edEntry) {
    try {
      const key = await importEd25519(publicKeys.ed25519SpkiB64);
      ed25519 = await globalThis.crypto.subtle.verify("Ed25519", key, base64ToBytes(edEntry.sig), toVerify);
    } catch {
      ed25519 = false;
    }
  }

  let mldsa44 = null;
  if (mldsaEntry && publicKeys.mldsa44B64) {
    try {
      mldsa44 = ml_dsa44.verify(base64ToBytes(mldsaEntry.sig), toVerify, base64ToBytes(publicKeys.mldsa44B64));
    } catch {
      mldsa44 = false;
    }
  }

  const valid = ed25519 === true && mldsa44 !== false;
  let statement = null;
  if (valid) {
    try {
      statement = JSON.parse(new TextDecoder().decode(payloadBytes));
    } catch {
      return { valid: false, ed25519, mldsa44, statement: null };
    }
  }
  return { valid, ed25519, mldsa44, statement };
}

export async function jcsDigestHex(obj) {
  assertIJson(obj);
  const bytes = enc.encode(JSON.stringify(cgCanon(obj)));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function statementOf(envelope) {
  return JSON.parse(new TextDecoder().decode(base64ToBytes(envelope.payload)));
}

export async function envelopeDigest(envelope) {
  return `sha256:${await jcsDigestHex(statementOf(envelope))}`;
}

export { base64ToBytes };
