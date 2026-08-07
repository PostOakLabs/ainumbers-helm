# Vendored reference — wiktor-k/ssh-sig

**Source:** https://github.com/wiktor-k/ssh-sig
**Pinned commit:** `cb28ef2c6415b918c6441eb6d19fab0916eeb3f5`
**License:** Apache-2.0 (see `LICENSE` in this directory — unmodified upstream text).

## What this is

`reference/` is an unmodified copy of the upstream TypeScript source for the
SSHSIG (`ssh-keygen -Y`) wire format: armor de/encoding, SSH wire-format
reader/writer, public-key parsing per key type, and the reference `verify()`
routine. Pinned per `SIGN-EXTSIG-1` / `SIGNING-SURFACES-BUILD-SPEC.md` §1
(phil GO-WITH-CONDITIONS) as the named reference for the wire format.

**This code is NOT executed by helmd.** It targets Deno/browser
`SubtleCrypto` and is kept here only as a citable, license-clean audit trail
for the wire-format decisions our own implementation makes. The actual
verifier helmd runs is `hub/extsig.mjs` — hand-written against
`node:crypto`, Ed25519-only, with the namespace-enforcement and
sk-key-rejection behavior `SIGN-EXTSIG-1` requires and this reference does
**not** provide out of the box (see below).

## Where our implementation diverges, and why

- **Namespace is checked and hardcoded, not passed through.** The reference
  `verifier.ts` `verify()` unconditionally writes the literal string `"file"`
  as the namespace when reconstructing the signed blob — it never compares
  against the namespace the signature itself declares, and never lets a
  caller assert an expected namespace. That is precisely the shape of bug
  behind the GitLab cross-protocol signature-reuse defect
  (gitlab-org/gitlab#386047): a verifier that accepts a signature made for
  a different context. `hub/extsig.mjs` hardcodes
  `HELM_SSHSIG_NAMESPACE = "helm-countersign@ainumbers.co"`, always compares
  it against the parsed signature's `namespace` field, and rejects on any
  mismatch — proven by `wrong_namespace.sig` in `fixtures/sshsig/` (a real
  `ssh-keygen -Y sign` output made with a different namespace).
- **`sk-ssh-ed25519@openssh.com` (FIDO/security-key) is explicitly
  rejected**, not attempted. The reference's U2F/`sk-*` signing-input
  construction (`verifier.ts` lines computing `u2f_data`) has no test
  vectors proven against real `ssh-keygen` FIDO output in this codebase or
  upstream's own fixtures, so `hub/extsig.mjs` refuses `sk-*` keys with a
  plain error rather than accept-and-hope (phil's condition #2).
- **Ed25519 only.** RSA/ECDSA parsing exists in the reference and in
  `formats.ts` here for completeness of the citation, but `hub/extsig.mjs`
  only implements the `ssh-ed25519` path — algorithm agility is a decision,
  not a default (phil's condition #3).
- **`node:crypto`, not `SubtleCrypto`.** The reference targets browser/Deno
  `crypto.subtle`; `hub/extsig.mjs` runs in helmd (Node) and uses
  `node:crypto`'s synchronous `verify()` with a JWK-imported raw Ed25519 key
  — same signed-blob construction (`SSHSIG` magic + namespace + reserved +
  hash_algorithm + digest, each SSH-string-framed), different crypto API.

## Roster format

`allowed_signers` parsing in `hub/extsig.mjs` follows the OpenSSH
`ssh-keygen(1)` `AllowedSignersFile` format directly (adopted, not
invented) — `principal[,principal...] [options] keytype base64-key
[comment]` per line, `#`-prefixed and blank lines ignored.
