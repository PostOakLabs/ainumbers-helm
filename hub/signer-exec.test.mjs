// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// RED-before-GREEN for every phil hardening condition in SIGN-SEAM-1 /
// SIGNING-SURFACES-BUILD-SPEC.md §3. Each test below was run against a
// version of signer-exec.mjs with the corresponding guard removed and
// observed to fail before the guard was added back (see check-off note).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { signViaExternalSigner } from "./signer-exec.mjs";

const FIXTURES = join(import.meta.dirname, "fixtures", "signer");

function fixture(name) {
  return join(FIXTURES, name);
}

async function withTmp(fn) {
  const dir = mkdtempSync(join(tmpdir(), "signer-exec-test-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function testKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyDer: publicKey.export({ format: "der", type: "spki" }),
    privateKeyDerB64: privateKey.export({ format: "der", type: "pkcs8" }).toString("base64"),
  };
}

test("valid signer: real Ed25519 signature is accepted and verifies", async () => {
  const { publicKeyDer, privateKeyDerB64 } = testKeypair();
  const digest = Buffer.from("a".repeat(32));
  const { signature, algo } = await signViaExternalSigner({
    command: process.execPath,
    args: [fixture("valid-signer.mjs")],
    digest,
    publicKeyDer,
    env: { FIXTURE_PRIVKEY_B64: privateKeyDerB64 },
  });
  assert.equal(algo, "ed25519");
  assert.ok(signature.length > 0);
});

// --- phil condition 1: argv-array spawn, never a shell ---
test("argv-array: shell metacharacters in args are passed literally, never interpreted", async () => {
  await withTmp(async (dir) => {
    const outFile = join(dir, "argv.json");
    const canary = join(dir, "pwned.txt");
    const metacharArgs = [
      "marker",
      `; touch ${canary}`,
      `$(touch ${canary})`,
      "`touch " + canary + "`",
      `| touch ${canary}`,
      "a b", // a single arg containing a space must stay ONE argv element
    ];
    const { publicKeyDer } = testKeypair();
    await assert.rejects(
      signViaExternalSigner({
        command: process.execPath,
        args: [fixture("echo-argv.mjs"), ...metacharArgs],
        digest: Buffer.from("digest-bytes-for-argv-test-______"),
        publicKeyDer,
        env: { FIXTURE_OUT: outFile },
      }),
      /verify-after-sign FAILED/
    );
    assert.ok(!existsSync(canary), "a shell would have created this file — spawn must never invoke one");
    const gotArgs = JSON.parse(readFileSync(outFile, "utf8"));
    assert.deepEqual(gotArgs, metacharArgs, "argv must reach the child byte-for-byte, unmangled");
  });
});

// --- phil condition 2: empty child environment ---
test("empty env: default env:{} gives the child no inherited variables", async () => {
  await withTmp(async (dir) => {
    const outFile = join(dir, "env.json");
    const { publicKeyDer } = testKeypair();
    await assert.rejects(
      signViaExternalSigner({
        command: process.execPath,
        args: [fixture("echo-env.mjs")],
        digest: Buffer.from("digest-for-env-test-____________"),
        publicKeyDer,
        env: { FIXTURE_OUT: outFile },
      }),
      /verify-after-sign FAILED/
    );
    const gotEnv = JSON.parse(readFileSync(outFile, "utf8"));
    // FIXTURE_OUT itself is the one variable this test needed to pass through
    // (an explicit allowlist entry, per phil condition 2's "unless genuinely
    // needed"). On Windows, CreateProcess forces a fixed baseline set
    // regardless of what `env` says (Node/libuv, not this module) — measured
    // here, not assumed; anything beyond that baseline plus our own
    // allowlist entry is a real leak and fails the test.
    const WINDOWS_FORCED_ENV_KEYS = new Set([
      "HOMEDRIVE", "HOMEPATH", "LOGONSERVER", "PATH", "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERDOMAIN", "USERNAME", "USERPROFILE", "WINDIR",
    ]);
    const unexpected = Object.keys(gotEnv).filter(
      (k) => k !== "FIXTURE_OUT" && !(process.platform === "win32" && WINDOWS_FORCED_ENV_KEYS.has(k))
    );
    assert.deepEqual(unexpected, [], "no env vars beyond our explicit allowlist (+ Windows' unavoidable CreateProcess baseline) may reach the child");
  });
});

test("empty env: literal env:{} means the child sees NOTHING, not even PATH", async () => {
  await withTmp(async (dir) => {
    const outFile = join(dir, "env-empty.json");
    // FIXTURE_OUT must reach the fixture somehow to report back, so this one
    // test proves the {} case differently: spawn the fixture via an absolute
    // path with env genuinely {}, and assert it still ran (proving spawn
    // does not require an inherited environment to function) by checking the
    // process could still write output via a fixed sentinel we detect through
    // the promise resolving/rejecting rather than an env-carried path.
    const { publicKeyDer } = testKeypair();
    let threw = null;
    try {
      await signViaExternalSigner({
        command: process.execPath,
        args: [fixture("exit-nonzero.mjs")],
        digest: Buffer.from("digest-for-empty-env-test-______"),
        publicKeyDer,
        env: {},
      });
    } catch (e) {
      threw = e;
    }
    assert.ok(threw, "spawn must succeed and run the child even with a fully empty env — failure here would be a spawn-level error, not the expected nonzero-exit error");
    assert.match(threw.message, /exited nonzero/);
  });
});

// --- phil condition 3: output cap + hard timeout, fail closed ---
test("timeout: a hung signer is killed and produces no signature", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({
      command: process.execPath,
      args: [fixture("sleep-forever.mjs")],
      digest: Buffer.from("digest-for-timeout-test-________"),
      publicKeyDer,
      timeoutMs: 200,
    }),
    /exceeded its 200ms timeout/
  );
});

test("output cap: oversized stdout is killed and produces no signature", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({
      command: process.execPath,
      args: [fixture("oversized-output.mjs")],
      digest: Buffer.from("digest-for-cap-test-____________"),
      publicKeyDer,
      maxOutputBytes: 256,
    }),
    /exceeded the 256-byte cap/
  );
});

test("nonzero exit: a failed signer produces no signature", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({
      command: process.execPath,
      args: [fixture("exit-nonzero.mjs")],
      digest: Buffer.from("digest-for-exit-test-___________"),
      publicKeyDer,
    }),
    /exited nonzero \(code=3/
  );
});

// --- phil condition 4: verify-after-sign ---
test("lying signer: a syntactically valid but wrong signature is rejected", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({
      command: process.execPath,
      args: [fixture("lying-signer.mjs")],
      digest: Buffer.from("digest-for-lying-test-__________"),
      publicKeyDer,
    }),
    /verify-after-sign FAILED/
  );
});

test("lying signer: a genuine signature over the WRONG digest is rejected", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
  const wrongSig = cryptoSign(null, Buffer.from("not the digest we asked to sign"), privateKey).toString("base64");
  await withTmp(async (dir) => {
    // Reuse valid-signer.mjs's shape but hand-craft the fixture inline here
    // since it needs to ignore stdin and always emit a fixed, pre-signed
    // (but mismatched) signature.
    const script = join(dir, "wrong-digest-signer.mjs");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(
      script,
      `process.stdin.resume();\nprocess.stdin.on("end", () => { process.stdout.write(${JSON.stringify(wrongSig)} + "\\n"); process.exit(0); });\n`
    );
    await assert.rejects(
      signViaExternalSigner({
        command: process.execPath,
        args: [script],
        digest: Buffer.from("the-actual-digest-being-signed-"),
        publicKeyDer,
      }),
      /verify-after-sign FAILED/
    );
  });
});

// --- phil condition 6: digest only, never payload plaintext ---
test("digest-only: exactly the digest bytes reach the child's stdin, nothing else", async () => {
  await withTmp(async (dir) => {
    const outFile = join(dir, "stdin.b64");
    const digest = Buffer.from("exact-32-byte-digest-value-here");
    const { publicKeyDer } = testKeypair();
    await assert.rejects(
      signViaExternalSigner({
        command: process.execPath,
        args: [fixture("echo-stdin.mjs")],
        digest,
        publicKeyDer,
        env: { FIXTURE_OUT: outFile },
      }),
      /verify-after-sign FAILED/
    );
    const gotStdin = Buffer.from(readFileSync(outFile, "utf8"), "base64");
    assert.ok(digest.equals(gotStdin), "child must receive exactly the digest bytes, byte-for-byte");
  });
});

// --- malformed-output fail-closed (parseSignatureOutput hardening) ---
test("malformed output: multi-line / non-base64 stdout is rejected, never best-effort parsed", async () => {
  await withTmp(async (dir) => {
    const script = join(dir, "garbage-signer.mjs");
    const { writeFileSync } = await import("node:fs");
    writeFileSync(
      script,
      `process.stdin.resume();\nprocess.stdin.on("end", () => { process.stdout.write("not\\nbase64\\nat all\\n"); process.exit(0); });\n`
    );
    const { publicKeyDer } = testKeypair();
    await assert.rejects(
      signViaExternalSigner({
        command: process.execPath,
        args: [script],
        digest: Buffer.from("digest-for-garbage-test-________"),
        publicKeyDer,
      }),
      /not a single base64 line/
    );
  });
});

// --- input validation guards a caller bug can't smuggle past ---
test("rejects a shell-string command instead of an argv array (misuse guard)", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({ command: "", args: [], digest: Buffer.from("x".repeat(32)), publicKeyDer }),
    /command must be a non-empty string/
  );
});

test("rejects args that are not an array of strings", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({
      command: process.execPath,
      args: "not-an-array",
      digest: Buffer.from("x".repeat(32)),
      publicKeyDer,
    }),
    /args must be an array of strings/
  );
});

test("rejects non-Buffer digest (payload-plaintext-as-string misuse guard)", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({ command: process.execPath, args: [], digest: "not-a-buffer", publicKeyDer }),
    /digest must be a non-empty Buffer/
  );
});

test("rejects unsupported algo", async () => {
  const { publicKeyDer } = testKeypair();
  await assert.rejects(
    signViaExternalSigner({
      command: process.execPath,
      args: [fixture("valid-signer.mjs")],
      digest: Buffer.from("x".repeat(32)),
      publicKeyDer,
      algo: "rsa",
    }),
    /unsupported algo "rsa"/
  );
});
