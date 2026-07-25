// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// helmd's own §27.2 signing identity (HELM-HA-1): a WebCrypto Ed25519
// keypair, distinct from keys.mjs's node:crypto daemon keypair because
// vendored/ocg/kernels/_proof.mjs's sign()/verify() (the SPEC.md §16
// eddsa-jcs-2022 DataIntegrityProof implementation every HA record uses)
// takes WebCrypto CryptoKey objects, not node:crypto KeyObjects. Reuses
// keys.mjs's passphrase file + AES-256-GCM blob format — one at-rest secret,
// two keypairs.
//
// This is the identity helmd signs WITH when IT is the party attesting —
// minting a role_binding record, or a checker countersignature after it has
// itself re-executed a kernel and matched hashes (recordReplay in
// ha-gate.mjs). A human approver's OWN identity is expected to be a
// browser-held key (ui/lib/ha-crypto.mjs) that never reaches this file —
// helmd only ever verifies those signatures, via did:key public-key
// resolution (see verifyHaRecordSignature), never holds the private key.
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { loadOrCreatePassphrase, encryptBlob, decryptBlob } from "./keys.mjs";
import { rawPubkeyToDidKey } from "./vendored/ocg/kernels/_proof.mjs";

// Returns { privateKey, publicKey (WebCrypto CryptoKeys), id (did:key) }.
export async function loadOrCreateHaIdentity() {
  const path = statePath("ha-identity.enc.json");
  const passphrase = loadOrCreatePassphrase();
  if (existsSync(path)) {
    chmodSync(path, 0o600);
    const blob = JSON.parse(readFileSync(path, "utf8"));
    const plaintext = decryptBlob(passphrase, blob);
    const { privateKey: privJwk, publicKey: pubJwk } = JSON.parse(plaintext.toString("utf8"));
    const privateKey = await globalThis.crypto.subtle.importKey("jwk", privJwk, { name: "Ed25519" }, true, ["sign"]);
    const publicKey = await globalThis.crypto.subtle.importKey("jwk", pubJwk, { name: "Ed25519" }, true, ["verify"]);
    return { privateKey, publicKey, id: await rawPubkeyToDidKey(publicKey) };
  }
  const pair = await globalThis.crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const privJwk = await globalThis.crypto.subtle.exportKey("jwk", pair.privateKey);
  const pubJwk = await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey);
  const blob = encryptBlob(passphrase, Buffer.from(JSON.stringify({ privateKey: privJwk, publicKey: pubJwk }), "utf8"));
  writeFileSync(path, JSON.stringify(blob), { mode: 0o600 });
  chmodSync(path, 0o600);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, id: await rawPubkeyToDidKey(pair.publicKey) };
}
