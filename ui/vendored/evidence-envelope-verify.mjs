// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Ported PINNED from PostOakLabs/ainumbers.git @ 34cd823a80da0b082327bb90f55b5e793f92ef16,
// chaingraph/kernels/art-652-verify-receipt.kernel.mjs (its verifyReceipt()/compute()
// pair, tool_id "art-652-verify-receipt") — offline verifier for AINumbers Evidence
// Envelope v0.1 receipts (research/EVIDENCE-ENVELOPE-V01-RATIFIED-2026-08-20.md,
// workspace-root AINumbers estate). DO NOT hand-edit the verification logic below —
// fix upstream (the site's art-652 kernel) and re-port; only the crypto-primitive
// substitutions noted below are intentional, permanent divergences.
//
// Ported directly from the site repo rather than routed through hub/vendored/ocg
// (unlike hash.mjs/proof.mjs/der.mjs in this directory): hub/vendored/ocg's whole-tree
// pin (scripts/vendor.config.json) predates art-652 and bumping it to pick up one new
// kernel would re-vendor several hundred unrelated kernel files. Out of scope for this
// port; resync this file by hand (same discipline PORT.md already documents for the
// other ui/vendored/*.mjs entries) if the upstream kernel's verifyReceipt() changes.
//
// Two deliberate primitive substitutions, neither a second implementation of a
// canonicalization or Merkle scheme (the divergence this repo's doctrine forbids):
//   1. Ed25519 signature verification via WebCrypto (globalThis.crypto.subtle),
//      not the ~4000-line noble/curves bundle the upstream kernel inlines for its
//      QuickJS zkVM guest (which has no WebCrypto). Same RFC 8032 EdDSA verify
//      algorithm; same pattern this repo's own ../lib/verify-envelope.mjs already
//      uses for its unrelated DSSE envelope signatures.
//   2. SHA-256 via WebCrypto's digest(), not noble/hashes. JCS canonicalization
//      itself is NOT reimplemented — cgCanon is imported from ./hash.mjs, the same
//      vendored canonicalizer ../lib/verify-envelope.mjs already uses, so the
//      signing preimage bytes are produced by the one JCS implementation this repo
//      has, not a second one.
// did:key (base58, multicodec) decoding and base64url (unpadded) decoding have no
// Web-platform equivalent, so those two small, deterministic encoders are ported
// byte-for-byte from the upstream kernel below (not primitives; no cryptographic
// judgment call either substitution or a straight port could silently get wrong).
import { cgCanon } from "./hash.mjs";

const enc = new TextEncoder();

function utf8Bytes(str) {
  return enc.encode(str);
}

function canonicalStringify(v) {
  return JSON.stringify(cgCanon(v));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

async function sha256Hex(bytes) {
  return bytesToHex(await sha256(bytes));
}

// base58 decode (matches the upstream kernel's local b58decode — did:key z-form uses
// the Bitcoin/IPFS base58 alphabet, no Web-platform decoder exists).
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(str) {
  let z = 0;
  while (z < str.length && str[z] === "1") z++;
  let num = 0n;
  for (let i = z; i < str.length; i++) {
    const c = B58.indexOf(str[i]);
    if (c < 0) throw new Error("bad base58");
    num = num * 58n + BigInt(c);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.unshift(Number(num & 0xffn));
    num >>= 8n;
  }
  return new Uint8Array([...Array(z).fill(0), ...bytes]);
}

// did:key (z-form, multicodec 0xed01) -> raw 32-byte Ed25519 public key.
function didKeyToPublicKey(did) {
  if (!did || did.indexOf("did:key:z") !== 0) throw new Error("not a did:key (z-form)");
  const prefixed = b58decode(did.slice("did:key:z".length));
  if (prefixed[0] !== 0xed || prefixed[1] !== 0x01) throw new Error("did:key is not Ed25519");
  const raw = prefixed.slice(2);
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return raw;
}

// base64url, UNPADDED (Evidence Envelope v0.1 delta #4). THROWS on malformed input so
// the caller's try/catch turns it into a verdict, not a crash.
const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function b64UrlToBytes(b64) {
  const s = String(b64 ?? "");
  if (/[+/=]/.test(s)) throw new Error("base64url must be unpadded and use -_ (not +/=)");
  if (s.length % 4 === 1) throw new Error("invalid base64url length");
  const out = [];
  let buffer = 0,
    bits = 0;
  for (let i = 0; i < s.length; i++) {
    const idx = B64URL_ALPHABET.indexOf(s[i]);
    if (idx === -1) throw new Error("invalid base64url character");
    buffer = (buffer << 6) | idx;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function base64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function importEd25519PublicKey(rawBytes) {
  const jwk = { kty: "OKP", crv: "Ed25519", x: base64urlEncode(rawBytes) };
  return globalThis.crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);
}

const SHA256_TAGGED_RE = /^sha256:[0-9a-f]{64}$/;

// Signing preimage: strip signatures + unprotected (remove, not null), JCS, sign/verify
// over the 32-byte SHA-256 digest of that JSON.
function stripForSigning(receipt) {
  const { signatures, unprotected, ...rest } = receipt;
  void signatures;
  void unprotected;
  return rest;
}

// previousReceiptHash preimage: JCS of the prior receipt INCLUDING signatures[],
// EXCLUDING unprotected{}.
function stripForChainHash(receipt) {
  const { unprotected, ...rest } = receipt;
  void unprotected;
  return rest;
}

// Verify one receipt. previousReceipt is optional — supplying it lets the chain-link
// check recompute previousReceiptHash instead of merely checking its shape. Mirrors
// the upstream kernel's verifyReceipt() check-for-check (same codes, same order),
// made async because WebCrypto digest/verify are promises where noble's are not.
export async function verifyEvidenceEnvelopeReceipt(receipt, previousReceipt) {
  const checks = [];
  const fail = (code, detail) => checks.push({ code, ok: false, detail: String(detail) });
  const pass = (code, detail) => checks.push({ code, ok: true, detail: String(detail) });
  const info = (code, detail) => checks.push({ code, ok: null, detail: String(detail) });

  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    fail("RECEIPT_MISSING", "no receipt object supplied");
    return { valid: false, checks };
  }

  if (receipt.schema === "ainumbers.evidence.v0.1") pass("SCHEMA_OK", receipt.schema);
  else fail("SCHEMA_INVALID", `schema=${JSON.stringify(receipt.schema ?? null)}`);

  const HASH_FIELDS = ["input_hash", "policy_digest", "execution_hash", "output_hash"];
  const badFields = HASH_FIELDS.filter((f) => receipt[f] != null && !SHA256_TAGGED_RE.test(receipt[f]));
  if (badFields.length) fail("HASH_FIELD_FORMAT_INVALID", badFields.join(","));
  else pass("HASH_FIELD_FORMAT_OK", HASH_FIELDS.filter((f) => receipt[f] != null).join(",") || "(none present)");

  const sigs = Array.isArray(receipt.signatures) ? receipt.signatures : [];
  if (sigs.length === 0) {
    fail("NO_SIGNATURES", "signatures[] empty or missing");
  } else {
    let digest;
    try {
      digest = await sha256(utf8Bytes(canonicalStringify(stripForSigning(receipt))));
    } catch (e) {
      fail("SIGNING_PREIMAGE_ERROR", e && e.message ? e.message : String(e));
      digest = null;
    }
    if (digest) {
      for (let i = 0; i < sigs.length; i++) {
        const sig = sigs[i];
        const label = `signatures[${i}]`;
        if (!sig || sig.alg !== "EdDSA") {
          fail("ALG_UNSUPPORTED", `${label} alg=${JSON.stringify(sig && sig.alg)}`);
          continue;
        }
        const kidBase = String(sig.kid || "").split("#")[0];
        const issuerBase = String(receipt.issuer_id || "").split("#")[0];
        if (!kidBase || kidBase !== issuerBase) {
          fail("KID_NOT_RESOLVABLE", `${label} kid=${sig.kid} issuer_id=${receipt.issuer_id}`);
          continue;
        }
        try {
          const pub = didKeyToPublicKey(kidBase);
          const sigBytes = b64UrlToBytes(sig.value);
          if (sigBytes.length !== 64) throw new Error(`signature must be 64 bytes, got ${sigBytes.length}`);
          const key = await importEd25519PublicKey(pub);
          const valid = (await globalThis.crypto.subtle.verify("Ed25519", key, sigBytes, digest)) === true;
          if (valid) pass("SIGNATURE_VALID", `${label} kid=${kidBase}`);
          else fail("SIGNATURE_INVALID", `${label} kid=${kidBase} digest=sha256:${bytesToHex(digest)}`);
        } catch (e) {
          fail("SIGNATURE_MALFORMED", `${label} ${e && e.message ? e.message : String(e)}`);
        }
      }
    }
  }

  if (receipt.previousReceiptHash != null) {
    const claimed = String(receipt.previousReceiptHash).replace(/^sha256:/, "").toLowerCase();
    if (previousReceipt && typeof previousReceipt === "object") {
      let expectedHex;
      try {
        expectedHex = await sha256Hex(utf8Bytes(canonicalStringify(stripForChainHash(previousReceipt))));
      } catch (e) {
        fail("PREV_LINK_PREIMAGE_ERROR", e && e.message ? e.message : String(e));
        expectedHex = null;
      }
      if (expectedHex != null) {
        if (claimed === expectedHex) pass("PREV_LINK_OK", `sha256:${expectedHex}`);
        else fail("PREV_LINK_MISMATCH", `expected sha256:${expectedHex}, receipt claims ${receipt.previousReceiptHash}`);
      }
    } else {
      info("PREV_LINK_UNVERIFIED", "previousReceiptHash present but no previous_receipt was supplied to check it against");
    }
  }

  const valid = checks.every((c) => c.ok !== false);
  return { valid, checks };
}
