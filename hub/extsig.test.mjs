// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  verifySshsig,
  verifyMinisig,
  parseSshsig,
  parseAllowedSigners,
  HELM_SSHSIG_NAMESPACE,
  CI_POLICY_SSHSIG_NAMESPACE,
} from "./extsig.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "fixtures", "sshsig");

function fixture(name) {
  return readFileSync(join(fixturesDir, name));
}

const message = fixture("message.txt");
const allowedSignersText = fixture("allowed_signers").toString("utf8");

test("HELM_SSHSIG_NAMESPACE is hardcoded, not configurable", () => {
  assert.equal(HELM_SSHSIG_NAMESPACE, "helm-countersign@ainumbers.co");
});

test("parseAllowedSigners reads the OpenSSH roster format", () => {
  const roster = parseAllowedSigners(allowedSignersText);
  assert.equal(roster.length, 1);
  assert.deepEqual(roster[0].principals, ["signer@helm-test"]);
  assert.equal(roster[0].keytype, "ssh-ed25519");
});

test("parseAllowedSigners ignores comments and blank lines", () => {
  const roster = parseAllowedSigners("# a comment\n\n" + allowedSignersText + "\n# trailing\n");
  assert.equal(roster.length, 1);
});

test("valid SSHSIG signature over correct namespace verifies", () => {
  const result = verifySshsig({
    armoredText: fixture("golden.sig").toString("utf8"),
    message,
    allowedSignersText,
    principal: "signer@helm-test",
  });
  assert.equal(result.ok, true);
  assert.equal(result.principal, "signer@helm-test");
  assert.match(result.keyFingerprintSha256, /^SHA256:/);
});

// phil condition #1 — the GitLab-class defect (gitlab-org/gitlab#386047):
// a signature made for a DIFFERENT namespace must never verify here, even
// though the key and message are otherwise correct. Cross-checked at
// fixture-generation time against real `ssh-keygen -Y verify`, which also
// rejects this fixture with "namespace does not match" (fixtures/sshsig/README.md).
test("wrong-namespace signature is rejected (namespace enforcement)", () => {
  const result = verifySshsig({
    armoredText: fixture("wrong_namespace.sig").toString("utf8"),
    message,
    allowedSignersText,
    principal: "signer@helm-test",
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /wrong namespace/);
});

test("tampered message is rejected", () => {
  const result = verifySshsig({
    armoredText: fixture("golden.sig").toString("utf8"),
    message: Buffer.from("this is not the signed content"),
    allowedSignersText,
    principal: "signer@helm-test",
  });
  assert.equal(result.ok, false);
});

// A signature that is internally self-consistent (valid Ed25519 sig over
// the right namespace+message) but signed by a DIFFERENT key than the one
// registered in the roster for this principal must still fail — proves the
// roster is actually consulted, not bypassed.
test("wrong-key signature (not the roster's key for this principal) is rejected", () => {
  const result = verifySshsig({
    armoredText: fixture("wrong_key.sig").toString("utf8"),
    message,
    allowedSignersText,
    principal: "signer@helm-test",
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /does not match the roster/);
});

test("unknown principal is rejected", () => {
  const result = verifySshsig({
    armoredText: fixture("golden.sig").toString("utf8"),
    message,
    allowedSignersText,
    principal: "nobody@example.com",
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /no ssh-ed25519 key registered/);
});

// phil condition #2 — sk-ssh-ed25519@openssh.com (FIDO) must be refused
// explicitly, never silently accepted or silently no-op'd.
test("sk-ssh-ed25519@openssh.com public key is explicitly rejected, not attempted", () => {
  // Hand-build a minimal SSHSIG blob whose public key algo is the FIDO
  // variant, to exercise the rejection path without needing a real FIDO key.
  const w = (buf) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(buf.length, 0);
    return Buffer.concat([len, buf]);
  };
  const pkAlgo = Buffer.from("sk-ssh-ed25519@openssh.com", "ascii");
  const key = Buffer.alloc(32, 1);
  const application = Buffer.from("ssh:", "ascii");
  const publickeyBlob = Buffer.concat([w(pkAlgo), w(key), w(application)]);
  const sigAlgo = Buffer.from("sk-ssh-ed25519@openssh.com", "ascii");
  const rawSig = Buffer.alloc(64, 2);
  const sigBlob = Buffer.concat([w(sigAlgo), w(rawSig)]);
  const body = Buffer.concat([
    Buffer.from("SSHSIG", "ascii"),
    Buffer.from([0, 0, 0, 1]),
    w(publickeyBlob),
    w(Buffer.from(HELM_SSHSIG_NAMESPACE, "utf8")),
    w(Buffer.alloc(0)),
    w(Buffer.from("sha512", "ascii")),
    w(sigBlob),
  ]);
  const armored = "-----BEGIN SSH SIGNATURE-----\n" + body.toString("base64") + "\n-----END SSH SIGNATURE-----\n";

  const parsed = parseSshsig(armored);
  assert.equal(parsed.publickey.pkAlgo, "sk-ssh-ed25519@openssh.com");

  const result = verifySshsig({ armoredText: armored, message, allowedSignersText, principal: "signer@helm-test" });
  assert.equal(result.ok, false);
  assert.match(result.reason, /FIDO\/security-key/);
});

test("malformed SSHSIG input throws (structural error, distinct from a failed verify)", () => {
  assert.throws(() => parseSshsig("not an sshsig blob"), /bad SSHSIG header/);
});

test("minisign is explicitly unsupported, never a silent no-op", () => {
  assert.throws(() => verifyMinisig(), /minisign verification is not supported/);
});

// FV-SSHSIG-POLICY-KEY-1 — the CI policy key signs under a namespace
// distinct from HELM_SSHSIG_NAMESPACE. Fixtures generated with a separate
// throwaway test key, real `ssh-keygen -Y sign`, cross-checked against
// real `ssh-keygen -Y verify` at generation time (fixtures/sshsig/README.md).
const ciPolicyMessage = fixture("ci_policy_message.txt");
const ciPolicyAllowedSigners = fixture("ci_policy_allowed_signers").toString("utf8");

test("CI_POLICY_SSHSIG_NAMESPACE is distinct from HELM_SSHSIG_NAMESPACE", () => {
  assert.equal(CI_POLICY_SSHSIG_NAMESPACE, "fv-policy-sign@ainumbers.co");
  assert.notEqual(CI_POLICY_SSHSIG_NAMESPACE, HELM_SSHSIG_NAMESPACE);
});

// RED before GREEN, in file order: this test runs first and demonstrates
// the failure mode the namespace parameter exists to prevent — a valid
// signature, correct key, correct roster entry, but verified against the
// WRONG expected namespace (the caller forgot to pass CI_POLICY_SSHSIG_NAMESPACE
// and got the HELM_SSHSIG_NAMESPACE default instead). Must fail.
test("[RED] CI-policy signature verified with the default (helm) namespace is rejected", () => {
  const result = verifySshsig({
    armoredText: fixture("ci_policy_golden.sig").toString("utf8"),
    message: ciPolicyMessage,
    allowedSignersText: ciPolicyAllowedSigners,
    principal: "ci-policy@helm-test",
    // namespace omitted -> defaults to HELM_SSHSIG_NAMESPACE, wrong for this sig
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /wrong namespace/);
});

// GREEN: the same signature, verified with the namespace it was actually
// signed under, passes.
test("[GREEN] CI-policy signature verified with CI_POLICY_SSHSIG_NAMESPACE succeeds", () => {
  const result = verifySshsig({
    armoredText: fixture("ci_policy_golden.sig").toString("utf8"),
    message: ciPolicyMessage,
    allowedSignersText: ciPolicyAllowedSigners,
    principal: "ci-policy@helm-test",
    namespace: CI_POLICY_SSHSIG_NAMESPACE,
  });
  assert.equal(result.ok, true);
  assert.equal(result.principal, "ci-policy@helm-test");
  assert.match(result.keyFingerprintSha256, /^SHA256:/);
});

test("CI-policy key signing under the wrong namespace on purpose is rejected", () => {
  const result = verifySshsig({
    armoredText: fixture("ci_policy_wrong_namespace.sig").toString("utf8"),
    message: ciPolicyMessage,
    allowedSignersText: ciPolicyAllowedSigners,
    principal: "ci-policy@helm-test",
    namespace: CI_POLICY_SSHSIG_NAMESPACE,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /wrong namespace/);
});

test("a different key signing under the CI-policy namespace is rejected (not in roster)", () => {
  const result = verifySshsig({
    armoredText: fixture("ci_policy_wrong_key.sig").toString("utf8"),
    message: ciPolicyMessage,
    allowedSignersText: ciPolicyAllowedSigners,
    principal: "ci-policy@helm-test",
    namespace: CI_POLICY_SSHSIG_NAMESPACE,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /does not match the roster/);
});

// A signature signed by the CI-policy key under the HELM namespace must
// never verify as a CI-policy signature — the two identities' signatures
// are not fungible even though both come from `ssh-keygen -Y sign`.
test("CI-policy key's helm-namespace signature does not verify as a CI-policy signature", () => {
  const result = verifySshsig({
    armoredText: fixture("ci_policy_signed_wrong_expected_namespace.sig").toString("utf8"),
    message: ciPolicyMessage,
    allowedSignersText: ciPolicyAllowedSigners,
    principal: "ci-policy@helm-test",
    namespace: CI_POLICY_SSHSIG_NAMESPACE,
  });
  assert.equal(result.ok, false);
  assert.match(result.reason, /wrong namespace/);
});
