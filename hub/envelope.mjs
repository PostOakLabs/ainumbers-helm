// Dual-sign DSSE/in-toto envelope emitter + verifier (D5, HELM-H2).
// Every signed Helm object (manifest, checkpoint, attestation, evidence bundle
// manifest, release manifest) is an in-toto Statement v1 inside a DSSE
// envelope, signed by BOTH Ed25519 (MUST) and ML-DSA-44 (SHOULD), using the
// RFC 9964 JOSE algorithm identifiers "EdDSA" / "ML-DSA-44". Payload
// canonicalization reuses cgCanon (JCS, RFC 8785) — the same canonicalizer
// the OCG kernels hash — so a statement's bytes never diverge from the OCG
// digest convention it's built alongside.
import { sign as cryptoSign, verify as cryptoVerify, createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { ml_dsa44 } from "./vendored/ocg/kernels/_proof.mjs";

export const IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json";
const HELM_PREDICATE_PREFIX = "https://ainumbers.co/helm/attestation/v1#";

export function helmPredicateType(kind) {
  return `${HELM_PREDICATE_PREFIX}${kind}`;
}

export function buildStatement({ subject, predicateType, predicate }) {
  const statement = {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject,
    predicateType,
    predicate,
  };
  assertIJson(statement);
  return statement;
}

// DSSE Pre-Authentication Encoding (PAE): binds payloadType into what gets
// signed so a signature can't be replayed across payload types.
function pae(payloadType, payloadBytes) {
  const enc = (s) => Buffer.from(s, "utf8");
  return Buffer.concat([
    enc("DSSEv1"), enc(" "),
    enc(String(Buffer.byteLength(payloadType, "utf8"))), enc(" "), enc(payloadType), enc(" "),
    enc(String(payloadBytes.length)), enc(" "), payloadBytes,
  ]);
}

function ed25519KeyId(publicKey) {
  return createHash("sha256").update(publicKey.export({ format: "der", type: "spki" })).digest("hex").slice(0, 16);
}

function mldsa44KeyId(publicKeyBytes) {
  return createHash("sha256").update(Buffer.from(publicKeyBytes)).digest("hex").slice(0, 16);
}

// keys = { ed25519: { privateKey }, mldsa44: { secretKey } } (see keys.mjs).
export function emitEnvelope(statement, keys) {
  const payloadBytes = Buffer.from(JSON.stringify(cgCanon(statement)), "utf8");
  const toSign = pae(DSSE_PAYLOAD_TYPE, payloadBytes);

  const edSig = cryptoSign(null, toSign, keys.ed25519.privateKey);
  const mldsaSig = ml_dsa44.sign(toSign, keys.mldsa44.secretKey);

  return {
    payloadType: DSSE_PAYLOAD_TYPE,
    payload: payloadBytes.toString("base64"),
    signatures: [
      { keyid: ed25519KeyId(keys.ed25519.publicKey), alg: "EdDSA", sig: edSig.toString("base64") },
      { keyid: mldsa44KeyId(keys.mldsa44.publicKey), alg: "ML-DSA-44", sig: Buffer.from(mldsaSig).toString("base64") },
    ],
  };
}

// publicKeys = { ed25519: KeyObject, mldsa44: Uint8Array } (see keys.mjs publicKeysOf()).
// Ed25519 is MUST: its absence or failure always fails the envelope.
// ML-DSA-44 is SHOULD: absence doesn't fail verification, but a present-and-wrong
// signature does (mldsa44 === false), so a tampered PQC co-signature is still caught.
// opts.strict (HELM-SEC-5, F6): flip to requiring BOTH signatures present-and-valid,
// for the day PQC becomes mandatory (D5). Default stays SHOULD/MUST per THREAT-MODEL §5.
export function verifyEnvelope(envelope, publicKeys, { strict = false } = {}) {
  if (envelope.payloadType !== DSSE_PAYLOAD_TYPE) {
    return { valid: false, ed25519: false, mldsa44: null, statement: null };
  }
  const payloadBytes = Buffer.from(envelope.payload, "base64");
  const toVerify = pae(envelope.payloadType, payloadBytes);

  const edEntry = envelope.signatures.find((s) => s.alg === "EdDSA");
  const mldsaEntry = envelope.signatures.find((s) => s.alg === "ML-DSA-44");

  const ed25519 = edEntry
    ? cryptoVerify(null, toVerify, publicKeys.ed25519, Buffer.from(edEntry.sig, "base64"))
    : false;
  const mldsa44 = mldsaEntry && publicKeys.mldsa44
    ? ml_dsa44.verify(new Uint8Array(Buffer.from(mldsaEntry.sig, "base64")), toVerify, publicKeys.mldsa44)
    : null;

  const valid = strict ? ed25519 === true && mldsa44 === true : ed25519 === true && mldsa44 !== false;
  let statement = null;
  if (valid) {
    try {
      statement = JSON.parse(payloadBytes.toString("utf8"));
    } catch {
      return { valid: false, ed25519, mldsa44, statement: null };
    }
  }
  return { valid, ed25519, mldsa44, statement };
}
