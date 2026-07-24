// Connector-token storage for browser-mode Helm (HELM-PHASE3-BUILD-SPEC.md
// P3-D8). Tokens are the ONLY thing the vault DEK ever encrypts — the vault
// record (wrapped DEK + PRF/passphrase KDF metadata) and the token blobs
// live in separate IndexedDB object stores so a leaked token row never
// carries the wrapped key material next to it.
//
// The IndexedDB adapter is injected so the encrypt/decrypt logic is unit
// testable under plain node:test without a browser; production callers omit
// `store` and get the real IndexedDB-backed one.
import { importDek, encryptWithDek, decryptWithDek } from "./vault-crypto.mjs";

const DB_NAME = "helm-vault";
const DB_VERSION = 1;
const TOKEN_STORE_NAME = "tokens";

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function openIndexedDbTokenStore() {
  const openReq = indexedDB.open(DB_NAME, DB_VERSION);
  openReq.onupgradeneeded = () => {
    const db = openReq.result;
    if (!db.objectStoreNames.contains(TOKEN_STORE_NAME)) db.createObjectStore(TOKEN_STORE_NAME);
  };
  return idbRequest(openReq).then((db) => ({
    async get(ref) {
      const tx = db.transaction(TOKEN_STORE_NAME, "readonly");
      const v = await idbRequest(tx.objectStore(TOKEN_STORE_NAME).get(ref));
      return v ?? null;
    },
    async set(ref, blobB64) {
      const tx = db.transaction(TOKEN_STORE_NAME, "readwrite");
      await idbRequest(tx.objectStore(TOKEN_STORE_NAME).put(blobB64, ref));
    },
    async delete(ref) {
      const tx = db.transaction(TOKEN_STORE_NAME, "readwrite");
      await idbRequest(tx.objectStore(TOKEN_STORE_NAME).delete(ref));
    },
  }));
}

// In-memory adapter matching the same {get,set,delete} shape — used by
// tests, and as a same-tab-only degraded mode if IndexedDB is ever
// unavailable (private-browsing edge cases on some engines).
export function createMemoryTokenStore() {
  const map = new Map();
  return {
    async get(ref) {
      return map.has(ref) ? map.get(ref) : null;
    },
    async set(ref, blobB64) {
      map.set(ref, blobB64);
    },
    async delete(ref) {
      map.delete(ref);
    },
  };
}

export class VaultTokenStore {
  constructor(dekBytes, store) {
    this._dekBytes = dekBytes;
    this._store = store;
    this._dekKey = null;
  }

  async _key() {
    if (!this._dekKey) this._dekKey = await importDek(this._dekBytes);
    return this._dekKey;
  }

  async setToken(ref, tokenObj) {
    // AAD binds this ciphertext to (ref, DB_VERSION) so a blob swapped into a
    // different token's IndexedDB slot fails to decrypt instead of opening
    // cleanly under the wrong ref (F12).
    const blob = await encryptWithDek(await this._key(), tokenObj, { ref, storeVersion: DB_VERSION });
    await this._store.set(ref, blob);
  }

  async getToken(ref) {
    const blob = await this._store.get(ref);
    if (blob === null) return null;
    return decryptWithDek(await this._key(), blob, { ref, storeVersion: DB_VERSION });
  }

  async deleteToken(ref) {
    await this._store.delete(ref);
  }
}
