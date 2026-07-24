import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.location) globalThis.location = { hostname: "ainumbers.co" };

import {
  enrollPrf,
  unlockPrf,
  enrollPassphrase,
  unlockPassphrase,
  unlockRecord,
  VaultNoPrfError,
  VaultWrongKeyError,
  VaultWeakPassphraseError,
  WRAP_METHOD,
  LOST_PASSKEY_COPY,
  PASSPHRASE_MIN_LENGTH,
} from "./vault.mjs";

// --- fake authenticators -----------------------------------------------
// Each fake models a real WebAuthn PublicKeyCredential shape closely enough
// to exercise vault.mjs's enrollment/unlock logic without a real device.

function fullPrfAuthenticator() {
  const rawId = crypto.getRandomValues(new Uint8Array(16)).buffer;
  const prfOutput = crypto.getRandomValues(new Uint8Array(32)).buffer;
  return {
    rawId,
    prfOutput,
    async create() {
      return { rawId, getClientExtensionResults: () => ({ prf: { enabled: true } }) };
    },
    async get() {
      return { getClientExtensionResults: () => ({ prf: { results: { first: prfOutput } } }) };
    },
  };
}

// Models the exact Windows-Hello-PRF-gap scenario from P3-D8: registration
// reports prf.enabled===true but a get() never actually returns output.
function enabledButNoOutputAuthenticator() {
  const rawId = crypto.getRandomValues(new Uint8Array(16)).buffer;
  return {
    rawId,
    async create() {
      return { rawId, getClientExtensionResults: () => ({ prf: { enabled: true } }) };
    },
    async get() {
      return { getClientExtensionResults: () => ({ prf: {} }) }; // no results.first
    },
  };
}

// Models Safari's QR cross-device ("hybrid") flow: no prf key at all.
function noPrfSupportAuthenticator() {
  const rawId = crypto.getRandomValues(new Uint8Array(16)).buffer;
  return {
    rawId,
    async create() {
      return { rawId, getClientExtensionResults: () => ({}) };
    },
    async get() {
      return { getClientExtensionResults: () => ({}) };
    },
  };
}

function asWebauthn(auth) {
  return { create: (...a) => auth.create(...a), get: (...a) => auth.get(...a) };
}

test("enrollPrf + unlockPrf: full round trip on a working PRF authenticator", async () => {
  const auth = fullPrfAuthenticator();
  const { dek, record } = await enrollPrf({ webauthn: asWebauthn(auth) });
  assert.equal(record.wrap_method, WRAP_METHOD.PRF);
  const unlocked = await unlockPrf(record, { webauthn: asWebauthn(auth) });
  assert.deepEqual(unlocked, dek);
});

test("enrollPrf throws VaultNoPrfError when prf.enabled is true but the test assertion returns no output", async () => {
  const auth = enabledButNoOutputAuthenticator();
  await assert.rejects(() => enrollPrf({ webauthn: asWebauthn(auth) }), VaultNoPrfError);
});

test("enrollPrf throws VaultNoPrfError when the authenticator never reports prf.enabled (Safari hybrid case)", async () => {
  const auth = noPrfSupportAuthenticator();
  await assert.rejects(() => enrollPrf({ webauthn: asWebauthn(auth) }), VaultNoPrfError);
});

test("unlockPrf throws VaultNoPrfError (not VaultWrongKeyError) when a later unlock attempt gets no PRF output", async () => {
  const auth = fullPrfAuthenticator();
  const { record } = await enrollPrf({ webauthn: asWebauthn(auth) });
  const degraded = enabledButNoOutputAuthenticator();
  degraded.rawId = auth.rawId; // same credential id, but this call path yields no PRF output
  await assert.rejects(() => unlockPrf(record, { webauthn: asWebauthn(degraded) }), VaultNoPrfError);
});

test("unlockPrf throws VaultWrongKeyError (not VaultNoPrfError) when PRF output doesn't match the enrolled one", async () => {
  const auth = fullPrfAuthenticator();
  const { record } = await enrollPrf({ webauthn: asWebauthn(auth) });

  const differentAuth = fullPrfAuthenticator(); // valid PRF output, just the wrong secret
  differentAuth.rawId = auth.rawId;
  await assert.rejects(() => unlockPrf(record, { webauthn: asWebauthn(differentAuth) }), VaultWrongKeyError);
});

test("enrollPassphrase + unlockPassphrase: round trip, wrong passphrase rejects", async () => {
  const { dek, record } = await enrollPassphrase("correct horse battery staple");
  assert.equal(record.wrap_method, WRAP_METHOD.PASSPHRASE);
  assert.deepEqual(await unlockPassphrase(record, "correct horse battery staple"), dek);
  await assert.rejects(() => unlockPassphrase(record, "wrong passphrase"), VaultWrongKeyError);
});

test("enrollPassphrase rejects a passphrase shorter than the minimum length (R15-F9)", async () => {
  const short = "a".repeat(PASSPHRASE_MIN_LENGTH - 1);
  await assert.rejects(() => enrollPassphrase(short), VaultWeakPassphraseError);
});

test("enrollPassphrase rejects a long but low-diversity passphrase (R15-F9)", async () => {
  const repetitive = "aaaaaaaaaaaaaaaaaaaa"; // long enough, but only 1 distinct char
  await assert.rejects(() => enrollPassphrase(repetitive), VaultWeakPassphraseError);
});

test("enrollPassphrase accepts a passphrase meeting the length + diversity floor", async () => {
  const { dek, record } = await enrollPassphrase("a".repeat(PASSPHRASE_MIN_LENGTH - 4) + "xyz1");
  assert.equal(record.wrap_method, WRAP_METHOD.PASSPHRASE);
  assert.ok(dek);
});

test("unlockRecord dispatches by wrap_method for both PRF and passphrase records", async () => {
  const auth = fullPrfAuthenticator();
  const prfEnrollment = await enrollPrf({ webauthn: asWebauthn(auth) });
  assert.deepEqual(await unlockRecord(prfEnrollment.record, { webauthn: asWebauthn(auth) }), prfEnrollment.dek);

  const passEnrollment = await enrollPassphrase("hunter2-hunter2");
  assert.deepEqual(await unlockRecord(passEnrollment.record, { passphrase: "hunter2-hunter2" }), passEnrollment.dek);
});

test("lost-passkey copy talks about reconnecting accounts, never claims the journal is lost", () => {
  assert.match(LOST_PASSKEY_COPY, /reconnect/i);
  assert.doesNotMatch(LOST_PASSKEY_COPY, /journal is lost|lose your journal|lose everything/i);
});
