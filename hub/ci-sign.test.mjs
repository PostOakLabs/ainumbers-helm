// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { signWithCiPolicyKey } from "./ci-sign.mjs";

// Skip cleanly (not a false green) if the runner has no ssh-keygen — the
// same real-binary dependency extsig's own fixtures already carry.
const hasSshKeygen = spawnSync("ssh-keygen", ["-?"], { stdio: "ignore" }).error === undefined;

test("signWithCiPolicyKey produces a signature that verifies under CI_POLICY_SSHSIG_NAMESPACE", { skip: !hasSshKeygen }, () => {
  // A throwaway key generated fresh for this test run — never the real
  // production ci-policy-key@ainumbers.co secret, which never touches a
  // test or a repo file.
  const dir = mkdtempSync(join(tmpdir(), "ci-sign-test-"));
  try {
    const keyPath = join(dir, "throwaway_key");
    execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "throwaway-ci-sign-test", "-f", keyPath], { stdio: "ignore" });
    const pubKey = execFileSync("ssh-keygen", ["-y", "-f", keyPath]).toString("utf8").trim();
    const allowedSignersText = `test-principal@ci-sign-test ${pubKey}\n`;

    const message = Buffer.from("ci-sign.mjs round-trip test payload");
    const { armoredText, keyFingerprintSha256 } = signWithCiPolicyKey({
      message,
      privateKeyPath: keyPath,
      allowedSignersText,
      principal: "test-principal@ci-sign-test",
    });

    assert.match(armoredText, /-----BEGIN SSH SIGNATURE-----/);
    assert.match(keyFingerprintSha256, /^SHA256:/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("signWithCiPolicyKey throws if the produced signature does not verify (wrong roster)", { skip: !hasSshKeygen }, () => {
  const dir = mkdtempSync(join(tmpdir(), "ci-sign-test-"));
  try {
    const keyPath = join(dir, "throwaway_key");
    execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "throwaway-ci-sign-test-2", "-f", keyPath], { stdio: "ignore" });

    // allowed_signers roster with a DIFFERENT key for the same principal —
    // the freshly produced signature must fail its own verify-after-sign.
    const otherKeyPath = join(dir, "other_key");
    execFileSync("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "other", "-f", otherKeyPath], { stdio: "ignore" });
    const otherPub = execFileSync("ssh-keygen", ["-y", "-f", otherKeyPath]).toString("utf8").trim();
    const wrongRoster = `test-principal@ci-sign-test ${otherPub}\n`;

    assert.throws(
      () =>
        signWithCiPolicyKey({
          message: Buffer.from("payload"),
          privateKeyPath: keyPath,
          allowedSignersText: wrongRoster,
          principal: "test-principal@ci-sign-test",
        }),
      /failed its own verify/
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
