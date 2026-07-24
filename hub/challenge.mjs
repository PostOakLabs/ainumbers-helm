// Signed-challenge daemon proof (P3-D9): before any client trusts a
// responder at 127.0.0.1:<port> enough to migrate data into it, the
// responder must prove it holds the private half of a stable per-install
// identity (keys.mjs's Ed25519 keypair, the same one that signs evidence
// envelopes) — not just that something answered on the port. A port
// squatter can echo bytes; it cannot produce a valid signature without the
// key file from ~/.helm.
import { sign as cryptoSign, verify as cryptoVerify, randomBytes, createPublicKey, createHash } from "node:crypto";

export function signChallenge(ed25519Keys) {
  const nonce = randomBytes(16).toString("base64url");
  const signature = cryptoSign(null, Buffer.from(nonce, "utf8"), ed25519Keys.privateKey).toString("base64");
  const publicKey = ed25519Keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  return { nonce, signature, publicKey };
}

// Pure verifier — no daemon state, callable from either side (server-side
// tests, or a future migration client). Never throws: a malformed challenge
// is just "not proven," not an error. NOTE (R15-F1): this alone is
// self-consistency, not identity — it proves the responder holds the
// private half of the publicKey IT SUPPLIED, which a port squatter can
// mint for itself. Callers MUST also compare fingerprintPublicKeyDer(publicKey)
// against a fingerprint delivered out-of-band (the `&fp=` pairing-link
// param, see token.mjs pairingUrl) before trusting the result.
export function verifyChallenge({ nonce, signature, publicKey }) {
  if (!nonce || !signature || !publicKey) return false;
  try {
    const pubKeyObj = createPublicKey({ key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" });
    return cryptoVerify(null, Buffer.from(nonce, "utf8"), pubKeyObj, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

// sha256 over the raw SPKI DER bytes, base64-encoded input (same shape
// signChallenge emits as `publicKey`) — the pinning material embedded in
// the pairing link and re-derived by the browser from a live challenge.
export function fingerprintPublicKeyDer(publicKeyBase64Der) {
  return `sha256:${createHash("sha256").update(Buffer.from(publicKeyBase64Der, "base64")).digest("hex")}`;
}
