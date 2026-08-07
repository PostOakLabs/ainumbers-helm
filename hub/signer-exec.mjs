// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// External-signer exec seam: a user-configured command signs helmd's
// pre-hashed digest — the "keys never leave our HSM" answer with zero SDKs.
// SIGN-SEAM-1 / SIGNING-SURFACES-BUILD-SPEC.md §3 (phil GO,
// research/PERSONA-phil-2026-08-06.md). Design model is the age-plugin
// protocol shape (C2SP/C2SP#5, FiloSottile/age) — argv-array exec,
// stdin/stdout framing only — NOT git's gpg.program, which shell-interpolates
// a configured string. No crypto of ours lives here: signature math is the
// existing node:crypto verify path (extsig.mjs's ed25519PublicKeyFromRaw /
// keys.mjs's DER conventions); this module only orchestrates the subprocess
// and refuses to trust what it returns.
//
// This is the highest-risk row of the SIGNING-SURFACES mini-wave precisely
// because it's not "just" crypto — it's command execution driven by config.
// Every guard below exists because phil named the specific failure it closes:
//   1. argv-array spawn, never a shell            -> spawn(cmd, args) with
//      shell:false (Node's default) and no string concatenation anywhere.
//   2. empty child environment                    -> env defaults to {}. On
//      Windows, CreateProcess forces a fixed OS baseline (PATH, SYSTEMROOT,
//      USERPROFILE, etc.) onto every child regardless of what `env` says —
//      that is Node/libuv, not this module, and is not secret-bearing; the
//      measured guarantee here is "no more than that baseline plus whatever
//      the caller explicitly allowlists," never a literal zero-key process
//      environment on every platform (POSIX genuinely gets one).
//   3. output cap + hard timeout, fail closed      -> byte-cap on stdout,
//      SIGKILL past deadline, both treated as "no signature", never partial.
//   4. verify-after-sign                           -> every returned
//      signature is verified against the declared public key before
//      acceptance; a lying/compromised signer is DETECTED, not trusted.
//   6. digest-only                                  -> callers pass a Buffer
//      digest, never document plaintext; this module has no code path that
//      could forward anything else to the child's stdin.
// (Condition 5, consent-gating the config change itself, lives in
// signer-config.mjs + the /signer/config* routes — not runtime exec.)
import { spawn } from "node:child_process";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";

export const SIGNER_TIMEOUT_MS_DEFAULT = 10_000;
export const SIGNER_MAX_OUTPUT_BYTES_DEFAULT = 8192;

// Digest sizes helmd actually produces (SHA-256 / SHA-512 family). Not a
// crypto check — just a sanity bound so a caller's bug (accidentally passing
// a multi-megabyte buffer) fails loudly here rather than being handed to an
// external process as "the digest."
const MAX_DIGEST_BYTES = 64;

function assertValidInputs({ command, args, digest, publicKeyDer, env, timeoutMs, maxOutputBytes }) {
  if (typeof command !== "string" || command.length === 0) {
    throw new Error("signer-exec: command must be a non-empty string (the executable path)");
  }
  if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
    throw new Error("signer-exec: args must be an array of strings — never a shell command line");
  }
  if (!Buffer.isBuffer(digest) || digest.length === 0 || digest.length > MAX_DIGEST_BYTES) {
    throw new Error(
      `signer-exec: digest must be a non-empty Buffer of at most ${MAX_DIGEST_BYTES} bytes (a pre-hashed digest, ` +
        "never document content)"
    );
  }
  if (!Buffer.isBuffer(publicKeyDer) || publicKeyDer.length === 0) {
    throw new Error("signer-exec: publicKeyDer must be a non-empty Buffer (SPKI DER, verify-after-sign target)");
  }
  if (env !== null && typeof env !== "object") {
    throw new Error("signer-exec: env must be an object (default {} — an explicit allowlist, never inherited)");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error("signer-exec: timeoutMs must be a positive integer");
  }
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes <= 0) {
    throw new Error("signer-exec: maxOutputBytes must be a positive integer");
  }
}

// Runs `command` with `args` (argv array — condition 1), feeds `digest` on
// stdin and closes it, and returns a parsed { signature, algo } only after
// verify-after-sign (condition 4) succeeds. Every other outcome — nonzero
// exit, timeout, oversized output, malformed output, failed verification —
// throws. There is no code path that returns a signature the caller did not
// independently verify here.
export async function signViaExternalSigner({
  command,
  args = [],
  digest,
  publicKeyDer,
  algo = "ed25519",
  env = {},
  timeoutMs = SIGNER_TIMEOUT_MS_DEFAULT,
  maxOutputBytes = SIGNER_MAX_OUTPUT_BYTES_DEFAULT,
}) {
  assertValidInputs({ command, args, digest, publicKeyDer, env, timeoutMs, maxOutputBytes });
  if (algo !== "ed25519") {
    throw new Error(`signer-exec: unsupported algo "${algo}" — ed25519 only at launch (agility is a decision, not a default)`);
  }

  const { code, signal, stdout, timedOut, killedForOversize, spawnError } = await runChild({
    command,
    args,
    input: digest,
    env: env ?? {},
    timeoutMs,
    maxOutputBytes,
  });

  if (spawnError) throw new Error(`signer-exec: failed to spawn signer: ${spawnError.message}`);
  if (timedOut) {
    throw new Error(`signer-exec: signer process exceeded its ${timeoutMs}ms timeout — killed, no signature accepted (fail closed)`);
  }
  if (killedForOversize) {
    throw new Error(
      `signer-exec: signer stdout exceeded the ${maxOutputBytes}-byte cap — killed, no signature accepted (fail closed)`
    );
  }
  if (code !== 0) {
    throw new Error(`signer-exec: signer exited nonzero (code=${code}, signal=${signal ?? "none"}) — no signature accepted`);
  }

  const signature = parseSignatureOutput(stdout);
  const publicKey = createPublicKey({ key: publicKeyDer, format: "der", type: "spki" });

  // Condition 4 — verify-after-sign. digest itself is the signed message:
  // Ed25519 signs its input directly (it is not fed a further hash), and
  // digest is already helmd's pre-hashed digest of the real document, so
  // this call is exactly "does the returned signature cover the thing we
  // asked the signer to sign" with no additional hashing step to get wrong.
  let valid;
  try {
    valid = cryptoVerify(null, digest, publicKey, signature);
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error(
      "signer-exec: verify-after-sign FAILED — the returned signature does not verify against the declared public " +
        "key. The signer tool is untrusted; rejecting rather than accepting a signature we cannot confirm."
    );
  }

  return { signature, algo };
}

// stdout is expected to be exactly one line of base64-encoded raw signature
// bytes (trailing whitespace tolerated). Anything else is a malformed-output
// fail-closed, never a best-effort parse.
function parseSignatureOutput(stdout) {
  const text = stdout.toString("utf8").trim();
  if (text.length === 0) throw new Error("signer-exec: signer produced empty stdout — no signature accepted");
  if (/\s/.test(text)) throw new Error("signer-exec: signer stdout was not a single base64 line — no signature accepted");
  let signature;
  try {
    signature = Buffer.from(text, "base64");
  } catch {
    throw new Error("signer-exec: signer stdout was not valid base64 — no signature accepted");
  }
  // Buffer.from(..., "base64") never throws on non-base64 chars — it drops
  // them silently — so round-trip the decode to actually detect garbage
  // instead of accepting a truncated/mis-decoded signature as if it parsed.
  if (signature.length === 0 || signature.toString("base64").replace(/=+$/, "") !== text.replace(/=+$/, "")) {
    throw new Error("signer-exec: signer stdout did not round-trip as base64 — no signature accepted");
  }
  return signature;
}

// Spawns the child and enforces the timeout/output-cap bounds. Isolated from
// signViaExternalSigner's verification logic so the two concerns — "did the
// process behave" and "do we trust what it said" — stay independently
// testable and neither can accidentally paper over the other.
function runChild({ command, args, input, env, timeoutMs, maxOutputBytes }) {
  return new Promise((resolve) => {
    let child;
    try {
      // shell:false is spawn's default — stated explicitly because it is the
      // entire reason condition 1 holds. args is passed as a real argv
      // array; command and each arg reach the OS's exec syscall verbatim,
      // with no shell ever parsing metacharacters, quoting, or `;`/`|`/`$()`.
      child = spawn(command, args, { shell: false, env, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    } catch (spawnError) {
      resolve({ code: null, signal: null, stdout: Buffer.alloc(0), timedOut: false, killedForOversize: false, spawnError });
      return;
    }

    let stdout = Buffer.alloc(0);
    let timedOut = false;
    let killedForOversize = false;
    let settled = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    timer.unref?.();

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    child.on("error", (spawnError) => {
      finish({ code: null, signal: null, stdout, timedOut, killedForOversize, spawnError });
    });

    child.stdout.on("data", (chunk) => {
      if (stdout.length >= maxOutputBytes) return; // already over cap; child is being killed
      if (stdout.length + chunk.length > maxOutputBytes) {
        killedForOversize = true;
        child.kill("SIGKILL");
        return;
      }
      stdout = Buffer.concat([stdout, chunk]);
    });
    // stderr is drained (never inspected) so a chatty signer can't backpressure-
    // stall the child on a full pipe; helmd's own diagnostics never depend on it.
    child.stderr.resume();

    child.on("close", (code, signal) => {
      finish({ code, signal, stdout, timedOut, killedForOversize, spawnError: null });
    });

    // Condition 6 — digest only. `input` is exactly the Buffer the caller
    // passed to signViaExternalSigner; nothing else is ever written to stdin.
    child.stdin.write(input);
    child.stdin.end();
  });
}
