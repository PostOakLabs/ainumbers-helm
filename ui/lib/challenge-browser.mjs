// Browser-side counterpart to hub/challenge.mjs (R15-F1/F2 fix, P3-D9).
// hub/challenge.mjs runs in Node (node:crypto) and signs; this module runs
// in the browser (WebCrypto) and verifies + pins. Two runtimes, same shapes
// — kept as a separate module rather than sharing challenge.mjs because
// ui/ ships to a browser and hub/ ships to Node, and the two never share a
// bundler (same rule handoff.mjs already documents).
//
// Ed25519 verify + SHA-256 digest are both plain WebCrypto (`crypto.subtle`
// global) — no vendoring needed in either runtime that supports it.

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Mirrors hub/challenge.mjs's fingerprintPublicKeyDer exactly (sha256 over
// the raw SPKI DER bytes) so a browser-computed fingerprint and a
// daemon-minted `&fp=` pairing-link value are directly comparable.
export async function fingerprintPublicKeyDer(publicKeyBase64Der) {
  const digest = await crypto.subtle.digest("SHA-256", base64ToBytes(publicKeyBase64Der));
  return `sha256:${bytesToHex(new Uint8Array(digest))}`;
}

// Pure signature check — SAME self-consistency-only limitation as
// hub/challenge.mjs's verifyChallenge: it proves the responder holds the
// private half of the publicKey it supplied, nothing about WHO that key
// belongs to. Never throws: a malformed challenge is just "not proven."
export async function verifyChallenge({ nonce, signature, publicKey }) {
  if (!nonce || !signature || !publicKey) return false;
  try {
    const key = await crypto.subtle.importKey("spki", base64ToBytes(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, base64ToBytes(signature), new TextEncoder().encode(nonce));
  } catch {
    return false;
  }
}

// THE wired check (R15-F1 fix): verifyChallenge alone is insufficient — a
// port squatter mints its own keypair and passes it every time (see
// challenge-browser.test.mjs's squat-triple case). This additionally
// requires the challenge's publicKey to fingerprint-match a value pinned
// from the daemon-identity-only channel (the `&fp=` pairing-link param,
// api.mjs loadFp()). Returns a verified-challenge object (truthy, carries
// `fingerprint` + `verifiedAt`) on success, or null — callers use the
// returned object, never a bare boolean, as the required proof-of-daemon
// parameter to migration.mjs's submitMigrationToDaemon (R15-F2 fix).
export async function verifyPinnedChallenge(challenge, pinnedFingerprint, now = Date.now()) {
  if (!pinnedFingerprint) return null;
  if (!(await verifyChallenge(challenge))) return null;
  const fingerprint = await fingerprintPublicKeyDer(challenge.publicKey);
  if (fingerprint !== pinnedFingerprint) return null;
  return { ...challenge, fingerprint, verifiedAt: now };
}
