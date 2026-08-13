// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// External counter-signature identities over artifact digests: OpenSSH
// SSHSIG (`ssh-keygen -Y`). Trust roster = OpenSSH `allowed_signers` file
// format (adopted, not invented). SIGN-EXTSIG-1 / SIGNING-SURFACES-BUILD-
// SPEC.md §1 (phil GO-WITH-CONDITIONS, research/PERSONA-phil-2026-08-06.md).
//
// Wire-format design reference: hub/vendored/ssh-sig (wiktor-k/ssh-sig,
// Apache-2.0, pinned commit cb28ef2c6415b918c6441eb6d19fab0916eeb3f5) — NOT
// executed; see hub/vendored/ssh-sig/REFERENCE.md for where and why this
// module diverges from it. Signature math is node:crypto only; the wrapper
// parsing below is our own code.
//
// Ed25519 only at launch (phil condition #3 — algorithm agility is a
// decision, not a default). sk-ssh-ed25519@openssh.com (FIDO/security-key)
// signatures are explicitly rejected, not attempted (phil condition #2 —
// no test vectors proven against real ssh-keygen FIDO output exist here or
// upstream, so this refuses rather than accept-and-hope).
//
// minisign is NOT implemented in this build — see verifyExternalSignature's
// throw below. No minisign binary was available in the build environment to
// produce real goldens (SIGN-EXTSIG-1 done-criterion #4 requires goldens
// from the real binary; fabricating them was explicitly declined). A
// minisign-support row is a follow-up, not silently done here.
import { createPublicKey, verify as cryptoVerify, createHash } from "node:crypto";

// Hardcoded, always enforced. A signature made under any other namespace is
// rejected regardless of key validity — this is phil condition #1, the
// direct fix for the GitLab cross-protocol signature-reuse defect
// (gitlab-org/gitlab#386047), where a verifier skipped this check.
export const HELM_SSHSIG_NAMESPACE = "helm-countersign@ainumbers.co";

// CI policy-signing namespace (FV-SSHSIG-POLICY-KEY-1) — machines sign
// under this namespace, never `HELM_SSHSIG_NAMESPACE`, so a policy-key
// signature and a human helm-countersign can never be cross-accepted for
// each other (same phil condition #1 the helm namespace enforces, applied
// to the second identity). The CI policy private key lives only in GitHub
// Actions secrets — see docs/TRUST.md "CI policy signing key".
export const CI_POLICY_SSHSIG_NAMESPACE = "fv-policy-sign@ainumbers.co";

const SSHSIG_MAGIC = "SSHSIG";
const SSHSIG_VERSION = 1;

// ---- SSH wire-format primitives (RFC 4251 §5 string/uint32 framing) ----

class Reader {
  #buf;
  #pos = 0;
  constructor(buf) {
    this.#buf = buf;
  }
  get isAtEnd() {
    return this.#pos === this.#buf.length;
  }
  readUint32() {
    if (this.#pos + 4 > this.#buf.length) throw new Error("extsig: truncated while reading uint32");
    const v = this.#buf.readUInt32BE(this.#pos);
    this.#pos += 4;
    return v;
  }
  readBytes(n) {
    if (this.#pos + n > this.#buf.length) throw new Error("extsig: truncated while reading bytes");
    const v = this.#buf.subarray(this.#pos, this.#pos + n);
    this.#pos += n;
    return v;
  }
  readString() {
    const len = this.readUint32();
    return this.readBytes(len);
  }
}

function writeString(buf) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

// ---- SSHSIG armor ----

function dearmor(armoredText) {
  const lines = armoredText.trim().split("\n").map((l) => l.trim());
  const first = lines.shift();
  if (first !== "-----BEGIN SSH SIGNATURE-----") {
    throw new Error(`extsig: bad SSHSIG header, expected "-----BEGIN SSH SIGNATURE-----" got: ${first}`);
  }
  const last = lines.pop();
  if (last !== "-----END SSH SIGNATURE-----") {
    throw new Error(`extsig: bad SSHSIG trailer, expected "-----END SSH SIGNATURE-----" got: ${last}`);
  }
  return Buffer.from(lines.join(""), "base64");
}

// Parses an armored SSHSIG blob into its structural fields. Throws on any
// malformed input. Ed25519 (`ssh-ed25519`) is fully parsed; `sk-ssh-
// ed25519@openssh.com` is recognized (so the caller gets a clean rejection
// rather than a generic parse error) but its flags/counter fields are not
// interpreted further.
export function parseSshsig(armoredText) {
  const reader = new Reader(dearmor(armoredText));

  const magic = reader.readBytes(6).toString("ascii");
  if (magic !== SSHSIG_MAGIC) throw new Error(`extsig: expected ${SSHSIG_MAGIC} magic, got: ${magic}`);
  const version = reader.readUint32();
  if (version !== SSHSIG_VERSION) throw new Error(`extsig: expected SSHSIG version 1, got: ${version}`);

  const publickeyBlob = reader.readString();
  const pkReader = new Reader(publickeyBlob);
  const pkAlgo = pkReader.readString().toString("ascii");
  let publickey;
  if (pkAlgo === "ssh-ed25519") {
    publickey = { pkAlgo, key: Buffer.from(pkReader.readString()) };
  } else if (pkAlgo === "sk-ssh-ed25519@openssh.com") {
    publickey = { pkAlgo, key: Buffer.from(pkReader.readString()), application: pkReader.readString().toString("utf8") };
  } else {
    publickey = { pkAlgo, raw: Buffer.from(publickeyBlob) };
  }

  const namespace = reader.readString().toString("utf8");
  const reserved = Buffer.from(reader.readString());
  const hashAlgorithm = reader.readString().toString("ascii");

  const sigBlob = reader.readString();
  const sigReader = new Reader(sigBlob);
  const sigAlgo = sigReader.readString().toString("ascii");
  const rawSignature = Buffer.from(sigReader.readString());

  if (!reader.isAtEnd) throw new Error("extsig: trailing bytes after SSHSIG structure");

  return { publickey, namespace, reserved, hashAlgorithm, sigAlgo, rawSignature };
}

function nodeHashName(sshHashAlgorithm) {
  if (sshHashAlgorithm === "sha256") return "sha256";
  if (sshHashAlgorithm === "sha512") return "sha512";
  throw new Error(`extsig: unsupported hash_algorithm: ${sshHashAlgorithm}`);
}

// Reconstructs the exact byte sequence ssh-keygen signs, per
// openssh-portable's PROTOCOL.sshsig:
//   MAGIC_PREAMBLE "SSHSIG" || namespace || reserved || hash_algorithm || H(message)
// each field SSH-string-framed except the magic.
function buildSignedBlob({ namespace, reserved, hashAlgorithm, message }) {
  const digest = createHash(nodeHashName(hashAlgorithm)).update(message).digest();
  return Buffer.concat([
    Buffer.from(SSHSIG_MAGIC, "ascii"),
    writeString(Buffer.from(namespace, "utf8")),
    writeString(reserved),
    writeString(Buffer.from(hashAlgorithm, "ascii")),
    writeString(digest),
  ]);
}

function ed25519PublicKeyFromRaw(rawKey) {
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: rawKey.toString("base64url") }, format: "jwk" });
}

// ---- OpenSSH allowed_signers roster ----

// Parses an OpenSSH `AllowedSignersFile` (ssh-keygen(1)): one entry per
// line, `principals [options] keytype base64-key [comment]`. `#`-prefixed
// and blank lines are ignored. Only ssh-ed25519 entries are usable by
// verifyExternalSignature; other key types parse (so a mixed roster doesn't
// throw) but never match.
export function parseAllowedSigners(text) {
  const entries = [];
  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    // principals field is comma-separated and may itself be quoted; options
    // (cert-authority, namespaces="...", valid-after=...) may precede the
    // keytype. We only need principals + keytype + key, so scan tokens and
    // take the first ssh-* / sk-ssh-* token as the keytype boundary.
    const tokens = line.split(/\s+/);
    if (tokens.length < 3) continue;
    const principalsField = tokens[0];
    let idx = 1;
    while (idx < tokens.length && !/^(ssh-|sk-ssh-|ecdsa-)/.test(tokens[idx])) idx++;
    if (idx >= tokens.length - 1) continue; // no keytype+key pair found
    const keytype = tokens[idx];
    const base64Key = tokens[idx + 1];
    const principals = principalsField.split(",").map((p) => p.replace(/^"|"$/g, ""));
    // The base64 blob is itself SSH-string-wire-framed ("ssh-ed25519" +
    // raw key), same shape as an SSHSIG's embedded public key — unwrap it
    // so `key` is directly comparable to parseSshsig()'s publickey.key.
    const blobReader = new Reader(Buffer.from(base64Key, "base64"));
    const blobAlgo = blobReader.readString().toString("ascii");
    if (blobAlgo !== keytype) continue; // malformed roster line — algo mismatch between field and blob
    const key = Buffer.from(blobReader.readString());
    entries.push({ principals, keytype, key });
  }
  return entries;
}

function findRosterKey(rosterEntries, principal, keytype) {
  return rosterEntries.find((e) => e.keytype === keytype && e.principals.includes(principal)) ?? null;
}

// Verifies an armored SSHSIG signature as a counter-signature over
// `message` (Buffer), attributed to `principal` per `allowedSignersText`.
// `namespace` defaults to `HELM_SSHSIG_NAMESPACE` (the original, still
// hardcoded-by-default helm-countersign identity) — pass
// `CI_POLICY_SSHSIG_NAMESPACE` explicitly to verify a machine policy
// signature instead. The check is always exact-match against whichever
// namespace the caller names; there is no namespace this function accepts
// implicitly.
//
// Returns { ok: true, principal, keyFingerprintSha256 } on success, or
// { ok: false, reason } — NEVER throws for a well-formed-but-invalid
// signature; throws only for structurally malformed SSHSIG input (a
// distinct failure mode a caller should treat as "not an SSHSIG blob at
// all", not as "signature check failed").
export function verifySshsig({ armoredText, message, allowedSignersText, principal, namespace = HELM_SSHSIG_NAMESPACE }) {
  const sig = parseSshsig(armoredText);

  if (sig.publickey.pkAlgo === "sk-ssh-ed25519@openssh.com" || sig.sigAlgo === "sk-ssh-ed25519@openssh.com") {
    return {
      ok: false,
      reason:
        "sk-ssh-ed25519@openssh.com (FIDO/security-key) signatures are not implemented in this build — no test " +
        "vectors proven against real ssh-keygen output exist. Refusing rather than accept-and-hope.",
    };
  }
  if (sig.publickey.pkAlgo !== "ssh-ed25519" || sig.sigAlgo !== "ssh-ed25519") {
    return { ok: false, reason: `unsupported key/signature algorithm: ${sig.publickey.pkAlgo}/${sig.sigAlgo} (Ed25519 only)` };
  }

  if (sig.namespace !== namespace) {
    return { ok: false, reason: `wrong namespace: signature declares "${sig.namespace}", verifier requires "${namespace}"` };
  }

  const roster = parseAllowedSigners(allowedSignersText);
  const rosterEntry = findRosterKey(roster, principal, sig.publickey.pkAlgo);
  if (!rosterEntry) {
    return { ok: false, reason: `no ${sig.publickey.pkAlgo} key registered for principal "${principal}" in allowed_signers` };
  }
  if (!rosterEntry.key.equals(sig.publickey.key)) {
    return { ok: false, reason: `signature's embedded key does not match the roster's registered key for principal "${principal}"` };
  }

  const signedBlob = buildSignedBlob({ namespace: sig.namespace, reserved: sig.reserved, hashAlgorithm: sig.hashAlgorithm, message });
  const publicKey = ed25519PublicKeyFromRaw(sig.publickey.key);
  const valid = cryptoVerify(null, signedBlob, publicKey, sig.rawSignature);
  if (!valid) return { ok: false, reason: "signature does not verify against the signed content" };

  const keyFingerprintSha256 = "SHA256:" + createHash("sha256").update(sig.publickey.key).digest("base64").replace(/=+$/, "");
  return { ok: true, principal, keyFingerprintSha256 };
}

// minisign is not implemented — explicit refusal per the decision recorded
// in SIGN-EXTSIG-1's check-off (no minisign binary available to produce
// real goldens; done-criterion #4 forbids fabricating them). A future row
// wires this in once goldens exist.
export function verifyMinisig() {
  throw new Error(
    "extsig: minisign verification is not supported in this build — no minisign binary was available to produce " +
      "real test goldens (SIGN-EXTSIG-1). SSHSIG (ssh-keygen -Y) is the only external counter-signature format " +
      "helmd accepts today."
  );
}
