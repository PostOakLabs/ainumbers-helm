// Pure WebCrypto primitives for the browser-mode vault (HELM-PHASE3-BUILD-SPEC.md
// P3-D8). No navigator/IndexedDB access here — that split is what lets this
// module run under plain node:test with the node:crypto webcrypto polyfill.
//
// The vault never wraps the journal (P3-D8, P3-D7): it wraps a random DEK,
// and the DEK is what encrypts connector tokens. A wrapping-key failure
// (wrong passphrase, wrong authenticator) can only ever fail to unwrap the
// DEK — it never touches journal data.

const WRAP_ALG = "AES-GCM";
const IV_LEN = 12;

// OWASP 2023 minimum for PBKDF2-HMAC-SHA256 (600k). Native SubtleCrypto only
// — deliberately not Argon2-wasm, to avoid adding a new vendored dependency
// for a fallback path that native PBKDF2 already covers adequately.
export const PBKDF2_ITERATIONS = 600_000;

export class VaultWrongKeyError extends Error {
  constructor() {
    super("wrong key: cannot unwrap vault (bad passphrase, wrong authenticator, or tampered blob)");
    this.name = "VaultWrongKeyError";
  }
}

function bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export { bytesToB64, b64ToBytes };

export function generateDek() {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function randomSalt(len = 16) {
  return crypto.getRandomValues(new Uint8Array(len));
}

// HKDF-expand the raw PRF output into an AES-256-GCM wrapping key. The salt
// is empty and the info string is fixed: the PRF output itself (bound to one
// WebAuthn credential + authenticator) is the only secret input:
export async function deriveWrapKeyFromPrf(prfOutput) {
  const ikm = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: new TextEncoder().encode("ainumbers-helm-vault-wrap-v1") },
    ikm,
    { name: WRAP_ALG, length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function derivePassphraseKdf(passphrase, salt, iterations = PBKDF2_ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    keyMaterial,
    { name: WRAP_ALG, length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function importDek(dekBytes) {
  return crypto.subtle.importKey("raw", dekBytes, WRAP_ALG, false, ["encrypt", "decrypt"]);
}

async function aesGcmSeal(key, plaintextBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: WRAP_ALG, iv }, key, plaintextBytes));
  const blob = new Uint8Array(iv.length + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, iv.length);
  return bytesToB64(blob);
}

async function aesGcmOpen(key, blobB64) {
  const blob = b64ToBytes(blobB64);
  const iv = blob.slice(0, IV_LEN);
  const ciphertext = blob.slice(IV_LEN);
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: WRAP_ALG, iv }, key, ciphertext));
  } catch {
    throw new VaultWrongKeyError();
  }
}

// Wraps/unwraps the random DEK under a derived wrapping key. Kept as
// (dek, wrapKey) at the call site (dek reads as the "thing being protected"
// first) even though the underlying primitive takes (key, plaintext).
export function wrapDek(dek, wrapKey) {
  return aesGcmSeal(wrapKey, dek);
}
export function unwrapDek(wrappedB64, wrapKey) {
  return aesGcmOpen(wrapKey, wrappedB64);
}

// Encrypts/decrypts connector tokens (or any JSON-serializable secret) under
// the unwrapped DEK. This is the ONLY thing the DEK ever protects.
export async function encryptWithDek(dekKey, plaintextObj) {
  return aesGcmSeal(dekKey, new TextEncoder().encode(JSON.stringify(plaintextObj)));
}

export async function decryptWithDek(dekKey, blobB64) {
  const bytes = await aesGcmOpen(dekKey, blobB64);
  return JSON.parse(new TextDecoder().decode(bytes));
}
