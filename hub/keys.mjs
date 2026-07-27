// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Signing key generation + at-rest storage.
// Keys are AES-256-GCM encrypted under a 32-byte passphrase that is held by
// vault.mjs's OS-keychain tier (macOS Keychain / Windows DPAPI / Linux Secret
// Service), NOT beside the ciphertext it protects. That separation is the
// whole point (HELM-KEYCHAIN-1): before it, `vault.key` and `keys.enc.json`
// sat in the same state dir, so copying the directory — a backup, a synced
// app-data folder, a stolen unencrypted disk — was sufficient to decrypt the
// daemon's signing keys with no code execution required.
//
// Installs predating this land with a `vault.key` on disk and migrate on the
// next load. The migration is deliberately write-verify-then-shred: the
// passphrase is written to the vault tier and READ BACK and compared before
// the legacy file is destroyed, so an interrupted or failed migration always
// leaves a recoverable state rather than an unopenable one.
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync, openSync, fsyncSync, closeSync, statSync, unlinkSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { vaultSet, vaultGetStrict, vaultDelete, vaultBackendFor } from "./vault.mjs";
import { ml_dsa44 } from "./vendored/ocg/kernels/_proof.mjs";

const SCRYPT_KEYLEN = 32;
const PASSPHRASE_REF_PREFIX = "helmd:at-rest-passphrase";
const LEGACY_PASSPHRASE_FILE = "vault.key";
const PASSPHRASE_REF_FILE = "passphrase-ref.json";

// The vault ref must be unique PER STATE DIR. macOS Keychain and Linux Secret
// Service are machine-global keyed by (service, account), so a fixed ref would
// make two installs on one machine — a HELM_HOME-overridden profile, a test
// run, a second user profile — silently share (and clobber) one passphrase.
// The ref is a non-secret label, so it is persisted in the state dir itself
// rather than derived from the directory path: that way moving or renaming
// ~/.helm carries the ref along instead of orphaning the keychain entry.
function passphraseRef() {
  const p = statePath(PASSPHRASE_REF_FILE);
  if (existsSync(p)) return JSON.parse(readFileSync(p, "utf8")).ref;
  const ref = `${PASSPHRASE_REF_PREFIX}:${randomBytes(8).toString("hex")}`;
  writeFileSync(p, JSON.stringify({ ref }, null, 2) + "\n", { mode: 0o600 });
  return ref;
}

// Blobs whose existence proves this install already has an at-rest passphrase.
// If one of these exists but no passphrase can be found, minting a new one is
// never the right move — it would silently orphan the blob (and, for
// keys.enc.json, silently change the identity every signed envelope names).
const CIPHERTEXTS = ["keys.enc.json", "ha-identity.enc.json"];

// Overwrite before unlinking: on the common case (a file whose blocks are
// rewritten in place) this destroys the passphrase bytes rather than merely
// unlinking the inode and leaving them recoverable. Not a guarantee on
// journaling/CoW filesystems or SSDs with wear levelling — it is a best-effort
// reduction of the dual-copy window, not an anti-forensic claim.
function shredFile(path) {
  try {
    const size = statSync(path).size;
    const fd = openSync(path, "r+");
    try {
      writeFileSync(fd, randomBytes(Math.max(size, 32)));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // best effort — proceed to unlink regardless
  }
  unlinkSync(path);
}

// Write the passphrase into the vault, verify it reads back byte-identical,
// and only then report success. On any mismatch the just-written entry is
// removed so the next boot retries cleanly from the legacy file.
function provisionPassphrase(ref, pass) {
  const { backend } = vaultSet(ref, { passphrase_b64: pass.toString("base64") });
  let readback = null;
  try {
    readback = vaultGetStrict(ref);
  } catch {
    readback = null;
  }
  const got = readback?.passphrase_b64 ? Buffer.from(readback.passphrase_b64, "base64") : null;
  if (!got || got.length !== pass.length || !timingSafeEqual(got, pass)) {
    vaultDelete(ref);
    throw new Error(
      `helmd: refusing to store the at-rest passphrase — wrote it to the "${backend}" vault tier but the ` +
        `read-back did not match. Nothing was deleted; the existing key material is untouched.`
    );
  }
  if (backend === "file-fallback" && !process.env.HELM_VAULT_PASSPHRASE) {
    console.warn(
      "helmd: no OS keychain reachable — the at-rest passphrase landed on the encrypted file tier. " +
        "This is supported, but it does NOT separate the key from the data it protects: set " +
        "HELM_VAULT_PASSPHRASE so the fallback key is derived rather than stored on disk."
    );
  }
  return backend;
}

// Returns the 32-byte at-rest passphrase, migrating a pre-keychain install on
// first call. THE ONLY passphrase call site in the daemon — ha-identity.mjs
// imports this function rather than implementing a second path (a second path
// only some consumers see is how half an install ends up on a stale secret).
function loadOrCreatePassphrase() {
  const legacyPath = statePath(LEGACY_PASSPHRASE_FILE);
  const ref = passphraseRef();

  // Already migrated. vaultGetStrict throws — loudly, by design — if the index
  // says the secret was stored but the tier no longer has it.
  if (vaultBackendFor(ref)) {
    const pass = Buffer.from(vaultGetStrict(ref).passphrase_b64, "base64");
    // Finish a migration interrupted between provisioning and shredding.
    if (existsSync(legacyPath)) shredFile(legacyPath);
    return pass;
  }

  // Pre-keychain install: adopt the existing passphrase, never a new one.
  if (existsSync(legacyPath)) {
    chmodSync(legacyPath, 0o600);
    const pass = readFileSync(legacyPath);
    provisionPassphrase(ref, pass);
    shredFile(legacyPath);
    return pass;
  }

  // Nothing anywhere. Minting is correct ONLY on a genuinely fresh install —
  // if encrypted blobs already exist, the passphrase has been lost and a fresh
  // one would orphan them permanently. Fail loudly instead.
  const orphaned = CIPHERTEXTS.filter((f) => existsSync(statePath(f)));
  if (orphaned.length > 0) {
    throw new Error(
      `helmd: the at-rest passphrase is missing but encrypted key material exists (${orphaned.join(", ")}). ` +
        `Refusing to generate a replacement: that would silently change this daemon's signing identity and ` +
        `permanently orphan every blob and previously signed envelope. Restore the OS keychain entry ` +
        `("${ref}"), or the ~/.helm state dir, from backup.`
    );
  }
  const pass = randomBytes(32);
  provisionPassphrase(ref, pass);
  return pass;
}

function encrypt(passphrase, plaintext) {
  const salt = randomBytes(16);
  const key = scryptSync(passphrase, salt, SCRYPT_KEYLEN);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

function decrypt(passphrase, blob) {
  const salt = Buffer.from(blob.salt, "base64");
  const key = scryptSync(passphrase, salt, SCRYPT_KEYLEN);
  const iv = Buffer.from(blob.iv, "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(blob.ciphertext, "base64")), decipher.final()]);
}

function generateKeys() {
  const ed25519 = generateKeyPairSync("ed25519");
  const mldsa44 = ml_dsa44.keygen();
  return { ed25519, mldsa44 };
}

function serializeKeys(keys) {
  return {
    ed25519: {
      privateKey: keys.ed25519.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
      publicKey: keys.ed25519.publicKey.export({ format: "der", type: "spki" }).toString("base64"),
    },
    mldsa44: {
      secretKey: Buffer.from(keys.mldsa44.secretKey).toString("base64"),
      publicKey: Buffer.from(keys.mldsa44.publicKey).toString("base64"),
    },
  };
}

function deserializeKeys(obj) {
  return {
    ed25519: {
      privateKey: createPrivateKey({ key: Buffer.from(obj.ed25519.privateKey, "base64"), format: "der", type: "pkcs8" }),
      publicKey: createPublicKey({ key: Buffer.from(obj.ed25519.publicKey, "base64"), format: "der", type: "spki" }),
    },
    mldsa44: {
      secretKey: new Uint8Array(Buffer.from(obj.mldsa44.secretKey, "base64")),
      publicKey: new Uint8Array(Buffer.from(obj.mldsa44.publicKey, "base64")),
    },
  };
}

// Returns { ed25519: { privateKey, publicKey } (KeyObjects), mldsa44: { secretKey, publicKey } (Uint8Array) }.
export function loadOrCreateKeys() {
  const path = statePath("keys.enc.json");
  const passphrase = loadOrCreatePassphrase();
  if (existsSync(path)) {
    chmodSync(path, 0o600);
    const blob = JSON.parse(readFileSync(path, "utf8"));
    const plaintext = decrypt(passphrase, blob);
    return deserializeKeys(JSON.parse(plaintext.toString("utf8")));
  }
  const keys = generateKeys();
  const blob = encrypt(passphrase, Buffer.from(JSON.stringify(serializeKeys(keys)), "utf8"));
  writeFileSync(path, JSON.stringify(blob), { mode: 0o600 });
  chmodSync(path, 0o600);
  return keys;
}

// Public-key-only view, safe to hand to verifyEnvelope() or export in attestations.
export function publicKeysOf(keys) {
  return { ed25519: keys.ed25519.publicKey, mldsa44: keys.mldsa44.publicKey };
}

// Exposed for release-keys.mjs (HELM-H8): the release signing keypair uses
// the same DER/base64 shape as the daemon keypair but is provisioned via
// env vars (CI secrets), not the at-rest passphrase-encrypted file.
export { serializeKeys, deserializeKeys, generateKeys };

// Exposed for ha-identity.mjs (HELM-HA-1): the §27.2 producer identity reuses
// this module's at-rest passphrase and AES-256-GCM blob format rather than a
// second encrypted-storage implementation. Keeping this the single passphrase
// entry point is load-bearing for HELM-KEYCHAIN-1 — a second accessor would
// let one consumer migrate while another kept reading a stale secret.
export { loadOrCreatePassphrase, encrypt as encryptBlob, decrypt as decryptBlob };

// Exposed for tests: the per-state-dir vault ref and the legacy filename the
// migration consumes.
export { passphraseRef as atRestPassphraseRef };
export const LEGACY_PASSPHRASE_FILENAME = LEGACY_PASSPHRASE_FILE;
