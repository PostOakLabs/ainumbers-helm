// Signing key generation + at-rest storage (D9 fallback tier).
// Real OS-keychain storage is HELM-H5's vault; this module owns a stable
// load/create API so H5 can swap the backing store underneath without
// touching envelope.mjs. Until then, keys are AES-256-GCM encrypted under a
// mode-0600 passphrase file — never written to disk in plaintext.
import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  scryptSync,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { ml_dsa44 } from "./vendored/ocg/kernels/_proof.mjs";

const SCRYPT_KEYLEN = 32;

function loadOrCreatePassphrase() {
  const path = statePath("vault.key");
  if (existsSync(path)) {
    chmodSync(path, 0o600);
    return readFileSync(path);
  }
  const pass = randomBytes(32);
  writeFileSync(path, pass, { mode: 0o600 });
  chmodSync(path, 0o600);
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
