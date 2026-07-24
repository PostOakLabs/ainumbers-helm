// Browser-mode vault (HELM-PHASE3-BUILD-SPEC.md P3-D8). WebAuthn PRF derives
// the key that wraps a random DEK; the DEK — never the PRF output, never the
// journal — is what encrypts connector tokens (see vault-token-store.mjs).
// A passphrase-KDF fallback ships alongside PRF from day one: some
// authenticators report `prf.enabled===true` without ever returning a value
// (pre-Feb-2026 Windows Hello builds), and Safari's QR cross-device
// ("hybrid") flow passes no PRF at all.
import {
  generateDek,
  deriveWrapKeyFromPrf,
  derivePassphraseKdf,
  randomSalt,
  wrapDek,
  unwrapDek,
  bytesToB64,
  b64ToBytes,
  PBKDF2_ITERATIONS,
} from "./vault-crypto.mjs";

export { VaultWrongKeyError } from "./vault-crypto.mjs";

// Thrown when WebAuthn PRF isn't usable on this authenticator/browser —
// distinct from VaultWrongKeyError (a real PRF/passphrase key that just
// doesn't unwrap this blob). Callers must not conflate the two in copy:
// "this device can't do that" reads very differently from "wrong password."
export class VaultNoPrfError extends Error {
  constructor(reason) {
    super(`WebAuthn PRF unavailable: ${reason}`);
    this.name = "VaultNoPrfError";
  }
}

export const WRAP_METHOD = Object.freeze({ PRF: "webauthn-prf", PASSPHRASE: "passphrase-kdf" });

export const LOST_PASSKEY_COPY =
  "Losing this passkey doesn't lose anything stored here — it only means reconnecting your accounts. Your journal isn't kept in the vault.";

const RP_NAME = "AINumbers Helm";

// Static, non-secret salt fed to the PRF eval on every enroll/unlock. It
// doesn't need to be secret — the authenticator-bound credential is the
// actual secret — it only needs to stay identical across calls so the
// derived PRF output (and therefore the AES wrap key) is stable.
const PRF_SALT = new TextEncoder().encode("ainumbers-helm-vault-prf-eval-v1");

function defaultWebauthn() {
  return typeof navigator !== "undefined" ? navigator.credentials : undefined;
}

function prfResultsOf(credentialLike) {
  return credentialLike?.getClientExtensionResults?.().prf;
}

// Enrolls a brand-new resident credential requesting the PRF extension, then
// IMMEDIATELY performs a get() test assertion (P3-D8's "test assertion
// confirming PRF-on-get"). `prf.enabled===true` at create() time is only a
// capability claim; only a get() that actually returns output proves PRF
// works end to end on this authenticator. A gap surfaces here, at
// enrollment, rather than silently locking the vault on the user's next
// unlock.
export async function enrollPrf({ webauthn = defaultWebauthn(), rpId = location.hostname } = {}) {
  if (!webauthn) throw new VaultNoPrfError("WebAuthn is not available in this environment");

  const credential = await webauthn.create({
    publicKey: {
      rp: { name: RP_NAME, id: rpId },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "helm-vault", displayName: "Helm vault" },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: {} },
    },
  });

  if (!prfResultsOf(credential)?.enabled) {
    throw new VaultNoPrfError("authenticator did not report prf.enabled at registration");
  }

  const testAssertion = await webauthn.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      allowCredentials: [{ id: credential.rawId, type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const prfOutput = prfResultsOf(testAssertion)?.results?.first;
  if (!prfOutput) {
    throw new VaultNoPrfError("registration succeeded but the test assertion returned no PRF output");
  }

  const dek = generateDek();
  const wrapKey = await deriveWrapKeyFromPrf(prfOutput);
  const wrappedDek = await wrapDek(dek, wrapKey);

  return {
    dek,
    record: {
      wrap_method: WRAP_METHOD.PRF,
      wrapped_dek: wrappedDek,
      credential_id: bytesToB64(new Uint8Array(credential.rawId)),
      kdf: { alg: "webauthn-prf" },
    },
  };
}

// Unlocks a PRF-wrapped record. Throws VaultNoPrfError if this
// authenticator/browser can't produce PRF output right now (fall back to
// passphrase), or VaultWrongKeyError if PRF output was produced but doesn't
// unwrap this particular blob (wrong authenticator/credential mismatch).
export async function unlockPrf(record, { webauthn = defaultWebauthn(), rpId = location.hostname } = {}) {
  if (!webauthn) throw new VaultNoPrfError("WebAuthn is not available in this environment");

  const assertion = await webauthn.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      allowCredentials: [{ id: b64ToBytes(record.credential_id), type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const prfOutput = prfResultsOf(assertion)?.results?.first;
  if (!prfOutput) {
    throw new VaultNoPrfError("assertion succeeded but returned no PRF output");
  }

  const wrapKey = await deriveWrapKeyFromPrf(prfOutput);
  return unwrapDek(record.wrapped_dek, wrapKey);
}

export async function enrollPassphrase(passphrase) {
  const dek = generateDek();
  const salt = randomSalt();
  const wrapKey = await derivePassphraseKdf(passphrase, salt);
  const wrappedDek = await wrapDek(dek, wrapKey);

  return {
    dek,
    record: {
      wrap_method: WRAP_METHOD.PASSPHRASE,
      wrapped_dek: wrappedDek,
      kdf: { alg: "PBKDF2-SHA256", salt: bytesToB64(salt), iterations: PBKDF2_ITERATIONS },
    },
  };
}

export async function unlockPassphrase(record, passphrase) {
  const salt = b64ToBytes(record.kdf.salt);
  const wrapKey = await derivePassphraseKdf(passphrase, salt, record.kdf.iterations);
  return unwrapDek(record.wrapped_dek, wrapKey);
}

// Convenience dispatcher: unlocks a stored record via whichever method it
// was enrolled with. Never falls PRF over to passphrase automatically — a
// caller who gets VaultNoPrfError decides whether to prompt for a passphrase
// enrollment, per the UX copy requirement (P3-D8).
export async function unlockRecord(record, opts) {
  if (record.wrap_method === WRAP_METHOD.PRF) return unlockPrf(record, opts);
  if (record.wrap_method === WRAP_METHOD.PASSPHRASE) return unlockPassphrase(record, opts?.passphrase);
  throw new Error(`unknown vault wrap_method: ${record.wrap_method}`);
}
