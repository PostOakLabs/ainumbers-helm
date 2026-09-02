// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// SD-JWT credential emission for helmd (HELM-SDJWT-EMIT-1). EMISSION ONLY:
// this module mints selectively-disclosable JWTs and nothing else — no
// wallet integration, no holder binding flow, no verifier network, no
// submission anywhere. A caller hands it claims + a disclosure frame + a
// signing key; it returns the compact SD-JWT serialization and an emission
// record.
//
// Two maturity layers, and the honesty split between them is the point:
//   - BASE profile — RFC 9901 (Selective Disclosure for JWTs, published
//     November 2025). Stable; described as ratified everywhere it appears.
//   - VC profile — SD-JWT VC claims/typ conventions. That specification is
//     STILL AN INTERNET-DRAFT (draft-ietf-oauth-sd-jwt-vc; at pin time -19,
//     in IESG Last Call). Every emitted record labels this layer
//     "tracks draft" with ratified:false, and the CLI help says the same.
//     Never present the VC layer as settled.
//
// Reproducibility: SD-JWT disclosure salts are random by construction, so an
// emission is only re-derivable if the salt source is recorded. Callers may
// pass a seedHex; salts then come from an HMAC-SHA256-CTR stream over that
// seed, and the same (seed, claims, frame, key, header) inputs reproduce the
// token byte-for-byte. The seed is recorded in the emission record marked
// issuer-private: anyone holding the seed plus the token can mount an
// offline brute-force against low-entropy disclosed values, so the seed
// record is evidence-bundle material, never something published beside the
// credential. Without a seed the record says reproducible:false.
//
// Vendored dependency: @sd-jwt/core (Apache-2.0, OpenWallet Foundation),
// RFC 9901 implementation, plus @owf/identity-common (its only runtime
// dependency). Both are byte-identical npm-tarball vendors pinned in
// hub/vendored/sd-jwt/MANIFEST.json — zero npm install (this repo keeps an
// empty dependencies map by policy), zero rewritten import paths. The bare
// specifier below resolves through the vendored node_modules/ walk-up.
import { createRequire } from "node:module";
import { createHash, createHmac, randomBytes, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const requireVendored = createRequire(join(dirname(fileURLToPath(import.meta.url)), "vendored", "sd-jwt", "MANIFEST.json"));
const { SDJwtInstance } = requireVendored("@sd-jwt/core");

// --- Maturity labels -------------------------------------------------------
// VC profile pin: draft-ietf-oauth-sd-jwt-vc-19 (2026-08-31), IESG Last Call
// ending 2026-09-15, not an RFC. This is a dated observation, recorded as one.

export const BASE_PROFILE = Object.freeze({
  key: "base",
  name: "SD-JWT (Selective Disclosure for JWTs)",
  spec: "RFC 9901",
  status: "Published RFC (November 2025)",
  ratified: true,
});

export const VC_PROFILE = Object.freeze({
  key: "vc",
  name: "SD-JWT VC (SD-JWT-based Verifiable Credentials)",
  tracks: "draft-ietf-oauth-sd-jwt-vc-19",
  status:
    "Active Internet-Draft (IETF OAuth WG), in IESG Last Call ending 2026-09-15 — tracks draft, NOT a ratified RFC (pinned 2026-09-01)",
  ratified: false,
  label: "tracks draft",
});

export function profileFor(key) {
  if (key === BASE_PROFILE.key) return BASE_PROFILE;
  if (key === VC_PROFILE.key) return VC_PROFILE;
  throw new Error(`sdjwt-emit: unknown profile "${key}" (expected "base" or "vc")`);
}

// Explicit typing per RFC 9901 section 9.11 ("Application and profiles of
// SD-JWT SHOULD be explicitly typed"); the VC profile's typ value is a MUST
// in draft -19 section 2.2.1 ("The typ value MUST use dc+sd-jwt"), which
// supersedes the older "vc+sd-jwt" value.
export const BASE_TYP = "sd-jwt";
export const VC_TYP = "dc+sd-jwt";

// draft -19 section 2.2.2.3: these claims MUST NOT be selectively disclosed
// ("vct#integrity" is the claim name with the '#'; the rest are plain keys).
const VC_NEVER_DISCLOSED = Object.freeze([
  "vct",
  "vct#integrity",
  "cnf",
  "iss",
  "nbf",
  "exp",
  "status",
  "aka_vcts",
]);

// --- Crypto adapters (node:crypto; helmd keys are node KeyObjects) ---------
// IANA hash names (RFC 9901's "_sd_alg" registry) -> node:crypto names.
const NODE_HASH_ALGS = Object.freeze({
  "sha-256": "sha256",
  "sha-384": "sha384",
  "sha-512": "sha512",
  "sha3-256": "sha3-256",
  "sha3-384": "sha3-384",
  "sha3-512": "sha3-512",
});

export function nodeHasher(data, alg) {
  const mapped = NODE_HASH_ALGS[alg];
  if (!mapped) {
    throw new Error(`sdjwt-emit: hash algorithm "${alg}" is not supported by the node hasher adapter (supported: ${Object.keys(NODE_HASH_ALGS).join(", ")})`);
  }
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  return new Uint8Array(createHash(mapped).update(buf).digest());
}

// HMAC-SHA256-CTR stream over the seed: each disclosure salt is the next
// `length` bytes, base64url-encoded. Core asks for 16 bytes per salt, which
// matches RFC 9901 section 9.3's 128-bit recommended entropy floor.
export function seededSaltGenerator(seedHex) {
  if (typeof seedHex !== "string" || !/^[0-9a-f]+$/i.test(seedHex) || seedHex.length < 32) {
    throw new Error("sdjwt-emit: seedHex must be a hex string of at least 32 characters (16 bytes)");
  }
  const seed = Buffer.from(seedHex, "hex");
  let counter = 0;
  let pool = Buffer.alloc(0);
  let poolPos = 0;
  return function saltGenerator(length) {
    const out = Buffer.alloc(length);
    let filled = 0;
    while (filled < length) {
      if (poolPos >= pool.length) {
        pool = createHmac("sha256", seed).update(Buffer.from(String(counter++))).digest();
        poolPos = 0;
      }
      const take = Math.min(pool.length - poolPos, length - filled);
      pool.copy(out, filled, poolPos, poolPos + take);
      poolPos += take;
      filled += take;
    }
    return out.toString("base64url");
  };
}

export function randomSaltGenerator() {
  return (length) => randomBytes(length).toString("base64url");
}

export function generateSeed() {
  return randomBytes(32).toString("hex");
}

// Ed25519 ("EdDSA", RFC 8032/7518) signer/verifier over node KeyObjects.
export function ed25519Signer(privateKey) {
  return (data) => cryptoSign(null, Buffer.from(data, "utf8"), privateKey).toString("base64url");
}

export function ed25519Verifier(publicKey) {
  return (data, sig) => cryptoVerify(null, Buffer.from(data, "utf8"), publicKey, Buffer.from(sig, "base64url"));
}

// --- Emitter ---------------------------------------------------------------

function vcFrameViolations(disclosureFrame) {
  const hits = [];
  if (disclosureFrame) {
    const top = disclosureFrame._sd;
    if (Array.isArray(top)) {
      for (const key of top) {
        if (VC_NEVER_DISCLOSED.includes(key)) hits.push(key);
      }
    }
    for (const key of VC_NEVER_DISCLOSED) {
      if (Object.prototype.hasOwnProperty.call(disclosureFrame, key)) hits.push(key);
    }
  }
  return hits;
}

export function createEmitter(config = {}) {
  const { seedHex, signer, signAlg = "EdDSA", verifier, hashAlg = "sha-256" } = config;
  if (typeof signer !== "function") throw new Error("sdjwt-emit: a signer function is required");
  const saltGenerator = seedHex != null ? seededSaltGenerator(seedHex) : randomSaltGenerator();
  return new SDJwtInstance({
    hasher: nodeHasher,
    hashAlg,
    saltGenerator,
    signer,
    signAlg,
    ...(verifier ? { verifier } : {}),
  });
}

// Emits one SD-JWT. Returns { token, record }:
//   token  — the compact SD-JWT serialization (issuer JWT ~ disclosures ~ [kb])
//   record — the JSON sidecar: maturity labels, salt-seed provenance, and the
//            inputs a re-emission must match. The record is issuer-private
//            whenever it carries a seed (see the header note).
export async function emitSdJwt({
  claims,
  disclosureFrame = undefined,
  profile = BASE_PROFILE.key,
  seedHex = undefined,
  signer,
  signAlg = "EdDSA",
  verifier = undefined,
  kid = undefined,
  hashAlg = "sha-256",
}) {
  const profileDesc = profileFor(profile);
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("sdjwt-emit: claims must be a JSON object");
  }

  if (profile === VC_PROFILE.key) {
    if (typeof claims.vct !== "string" || claims.vct.length === 0) {
      throw new Error('sdjwt-emit: VC profile requires a non-empty "vct" claim (draft -19 section 2.2.2.3)');
    }
    const hits = vcFrameViolations(disclosureFrame);
    if (hits.length > 0) {
      throw new Error(
        `sdjwt-emit: VC profile forbids selectively disclosing ${hits.join(", ")} (draft -19 section 2.2.2.3)`
      );
    }
  }

  const typ = profile === VC_PROFILE.key ? VC_TYP : BASE_TYP;
  const header = { typ, ...(kid != null ? { kid } : {}) };

  const emitter = createEmitter({ seedHex, signer, signAlg, verifier, hashAlg });
  const token = await emitter.issue(claims, disclosureFrame, { header });

  const record = {
    artifact: "sd-jwt",
    profile:
      profile === VC_PROFILE.key
        ? { ...VC_PROFILE }
        : { ...BASE_PROFILE, note: "emitted without VC profile claims; no draft-tracked layer is present in this token" },
    headerTyp: typ,
    hashAlg,
    signAlg,
    ...(kid != null ? { kid } : {}),
    disclosureFrame: disclosureFrame === undefined ? null : disclosureFrame,
    saltSeed: {
      seed: seedHex != null ? seedHex : null,
      generator: seedHex != null ? "HMAC-SHA256-CTR over seed (base64url slices, 16 bytes per salt)" : "node:crypto randomBytes (NOT reproducible)",
      saltBits: 128,
      handling:
        seedHex != null
          ? "issuer-private: the seed re-derives every disclosure salt and enables offline brute-force of low-entropy claims; never publish it beside the token"
          : null,
    },
    reproducible: seedHex != null,
  };
  return { token, record };
}

// Holder-side selection: returns the presented compact SD-JWT with only the
// disclosures the frame reveals. Plain (non-disclosable) claims are always in
// the signed payload; frame keys pick which _sd disclosures ride along.
export async function presentSdJwt(token, presentationFrame) {
  const presenter = new SDJwtInstance({ hasher: nodeHasher });
  return presenter.present(token, presentationFrame);
}

// Verifies issuer signature + digest consistency and returns the recovered
// claims. Works on both full and presented tokens.
export async function verifySdJwt(token, { verifier, ...verifyOptions } = {}) {
  if (typeof verifier !== "function") throw new Error("sdjwt-emit: a verifier function is required");
  const checker = new SDJwtInstance({ hasher: nodeHasher, verifier });
  return checker.verify(token, verifyOptions);
}
