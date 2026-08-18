// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Browser-held §27.2 approver identity (HELM-HA-1 §1 item 4 — "sign in-
// browser (keys local)"). helmd NEVER holds a human approver's private key:
// this module generates and persists one Ed25519 keypair per browser
// profile in localStorage, and every approve/reject/annotation record is
// signed HERE before it ever reaches the daemon (POST /ha/records verifies
// the signature server-side but never sees the private key). Distinct from
// hub/ha-identity.mjs, which is helmd's OWN identity for records IT mints
// (role_binding, the post-replay approval) — two different signers for two
// different accountable parties.
//
// Pure WebCrypto, same discipline as vault-crypto.mjs: no navigator-only
// APIs beyond localStorage, so this is unit-testable under node:test with
// Node's webcrypto + a localStorage polyfill if a suite needs one.
import { sign, rawPubkeyToDidKey } from "../vendored/proof.mjs";

const textEncoder = new TextEncoder();

const STORAGE_KEY = "helm.ha.identity";

async function generate() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const id = await rawPubkeyToDidKey(pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, privateJwk, publicJwk, id };
}

// Loads the browser's persisted approver identity, minting one on first use.
// Returns { privateKey, publicKey (CryptoKeys), id (did:key) }.
export async function loadOrCreateBrowserIdentity() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (raw) {
    const { privateJwk, publicJwk, id } = JSON.parse(raw);
    const privateKey = await crypto.subtle.importKey("jwk", privateJwk, { name: "Ed25519" }, true, ["sign"]);
    const publicKey = await crypto.subtle.importKey("jwk", publicJwk, { name: "Ed25519" }, true, ["verify"]);
    return { privateKey, publicKey, id };
  }
  const identity = await generate();
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ privateJwk: identity.privateJwk, publicJwk: identity.publicJwk, id: identity.id }));
  return identity;
}

// Builds + signs one §27.2 record. `nowISO` is caller-supplied (the record's
// own `timestamp`/proof `created` fields — determinism discipline matches
// every other signer in this codebase, never Date.now() buried in here).
export async function signHaRecord({ recordType, role, subjectHash, identityId, decision, reasonCode, override, nowISO }, identity) {
  const unsigned = {
    record_type: recordType,
    role,
    subject_hash: subjectHash,
    identity: { id: identityId ?? identity.id },
    ...(decision ? { decision } : {}),
    ...(reasonCode ? { reason_code: reasonCode } : {}),
    ...(override ? { override } : {}),
    timestamp: nowISO,
  };
  return sign(unsigned, { verificationMethod: `${identity.id}#key-1`, created: nowISO, privateKey: identity.privateKey });
}

// HELM-MAKERCHECKER-BUILD-SPEC.md MC-4/MC-1.2: signs a raw bundle_digest
// entirely client-side, with no server round-trip — the checker (or maker)
// never needs helmd reachable to PRODUCE this, only to submit it (MC-5.1).
// Mirrors hub/ha-gate.mjs's own signBundleDigest exactly (raw Ed25519 over
// the UTF8 digest bytes, alg "EdDSA" — never the WebCrypto algorithm name,
// see HELMALG-FIX-1) so the two sides of one signature scheme never drift.
export async function signBundleDigest(identity, bundleDigest) {
  const sig = await crypto.subtle.sign("Ed25519", identity.privateKey, textEncoder.encode(bundleDigest));
  return { keyid: identity.id, sig: btoa(String.fromCharCode(...new Uint8Array(sig))), alg: "EdDSA" };
}
