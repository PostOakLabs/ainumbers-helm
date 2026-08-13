// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// CI-side `ssh-keygen -Y sign` wrapper for the CI policy signing key.
// Machines sign under `CI_POLICY_SSHSIG_NAMESPACE` (hub/extsig.mjs) using
// a dedicated Ed25519 key that never leaves GitHub Actions secrets. This
// module does not read the secret itself; the workflow step writes it to
// a private temp file first (0600, workflow tmp dir, gitignored by
// construction) and passes that path in. This module's only job is
// invoking the real `ssh-keygen -Y sign` binary and handing back the
// armored signature, verified round-trip via extsig.mjs before it is
// trusted: a signer is checked, not assumed.
//
// No shell: spawn() gets a literal argv array, never a concatenated
// string, same discipline as hub/signer-exec.mjs.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, unlinkSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifySshsig, CI_POLICY_SSHSIG_NAMESPACE } from "./extsig.mjs";

// Signs `message` (Buffer) with the Ed25519 private key at `privateKeyPath`
// under `CI_POLICY_SSHSIG_NAMESPACE`, using the real `ssh-keygen -Y sign`
// binary (never a hand-rolled signer — goldens and production signatures
// come from the same code path). Returns the armored SSHSIG text.
//
// Throws if `ssh-keygen` is missing, exits nonzero, or produces a
// signature this module's own verifier then rejects — a signer that lies
// about succeeding must not be trusted silently.
export function signWithCiPolicyKey({ message, privateKeyPath, allowedSignersText, principal }) {
  const workDir = mkdtempSync(join(tmpdir(), "ci-sign-"));
  const messagePath = join(workDir, "message");
  const sigPath = `${messagePath}.sig`;
  try {
    writeFileSync(messagePath, message);
    const result = spawnSync(
      "ssh-keygen",
      ["-Y", "sign", "-f", privateKeyPath, "-n", CI_POLICY_SSHSIG_NAMESPACE, messagePath],
      { stdio: ["ignore", "pipe", "pipe"] }
    );
    if (result.status !== 0) {
      throw new Error(`ci-sign: ssh-keygen -Y sign exited ${result.status}: ${result.stderr?.toString("utf8") ?? ""}`);
    }
    const armoredText = readFileSync(sigPath, "utf8");

    // Verify-after-sign, same discipline as hub/signer-exec.mjs — a signer
    // that produced a well-formed-looking but non-verifying blob (wrong
    // key on disk, corrupted secret) must fail loudly here, not downstream.
    const verified = verifySshsig({
      armoredText,
      message,
      allowedSignersText,
      principal,
      namespace: CI_POLICY_SSHSIG_NAMESPACE,
    });
    if (!verified.ok) {
      throw new Error(`ci-sign: freshly produced signature failed its own verify: ${verified.reason}`);
    }

    return { armoredText, keyFingerprintSha256: verified.keyFingerprintSha256 };
  } finally {
    try {
      unlinkSync(messagePath);
    } catch {}
    try {
      unlinkSync(sigPath);
    } catch {}
  }
}
