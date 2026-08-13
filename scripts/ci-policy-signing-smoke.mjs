// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// CI-side smoke test for the real ci-policy-key@ainumbers.co secret.
// Writes CI_POLICY_SSHSIG_PRIVATE_KEY
// to a private temp file, signs a canary payload with hub/ci-sign.mjs,
// and verifies it against docs/allowed_signers through hub/extsig.mjs.
// Run manually via .github/workflows/ci-policy-signing-smoke.yml
// (workflow_dispatch) — never on push/PR, so an unset secret never reds
// normal CI.
import { mkdtempSync, writeFileSync, chmodSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { signWithCiPolicyKey } from "../hub/ci-sign.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

const privateKey = process.env.CI_POLICY_SSHSIG_PRIVATE_KEY;
if (!privateKey || privateKey.trim().length === 0) {
  console.error(
    "ci-policy-signing-smoke: CI_POLICY_SSHSIG_PRIVATE_KEY is not set. " +
      "This is expected until the secret is installed. Nothing to sign, " +
      "failing so a run against a missing secret is never mistaken for a passing smoke test."
  );
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "ci-policy-smoke-"));
const keyPath = join(dir, "ci_policy_key");
try {
  writeFileSync(keyPath, privateKey.endsWith("\n") ? privateKey : `${privateKey}\n`, { mode: 0o600 });
  chmodSync(keyPath, 0o600);

  const allowedSignersText = readAllowedSigners();
  const message = Buffer.from(`ci-policy-signing-smoke canary @ ${new Date().toISOString()}`);

  const { armoredText, keyFingerprintSha256 } = signWithCiPolicyKey({
    message,
    privateKeyPath: keyPath,
    allowedSignersText,
    principal: "ci-policy-key@ainumbers.co",
  });

  console.log("ci-policy-signing-smoke: OK");
  console.log(`  fingerprint: ${keyFingerprintSha256}`);
  console.log(`  signature length: ${armoredText.length} bytes`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

function readAllowedSigners() {
  return readFileSync(join(repoRoot, "docs", "allowed_signers"), "utf8");
}
