// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// Persisted config for the external-signer exec seam (SIGN-SEAM-1). Kept in
// its own state file (signer-config.json), separate from config.json, so
// writing it always goes through the consent-ticket-gated HTTP route in
// server.mjs (handleSignerConfigUpdate) rather than the plain file-edit path
// config.json's other fields use — phil condition #5: a signer-command
// change is key access and must never be reachable without the human
// consent step the paired UI shows before it POSTs.
//
// The file holds no secret: command/args/env-allowlist/pubkey are all things
// the operator already knows (they typed them in) and the pubkey is public
// by definition. It is not passphrase-encrypted like keys.enc.json.
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { statePath } from "./state-dir.mjs";

const CONFIG_FILE = "signer-config.json";

// Validates the shape a caller (the /signer/config route) hands in, before
// it's ever persisted or spawned. Throws with a specific reason on the first
// violation rather than silently coercing — a malformed config here is a
// user-authorship mistake worth surfacing, not papering over.
export function validateSignerConfig(input) {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("signer-config: expected an object");
  }
  const { command, args, env, algo, publicKeyDerBase64, timeoutMs, maxOutputBytes } = input;

  if (typeof command !== "string" || command.trim().length === 0) {
    throw new Error("signer-config: command must be a non-empty string (the executable path)");
  }
  const cleanArgs = args ?? [];
  if (!Array.isArray(cleanArgs) || !cleanArgs.every((a) => typeof a === "string")) {
    throw new Error("signer-config: args must be an array of strings — never a shell command line");
  }
  const cleanEnv = env ?? {};
  if (cleanEnv === null || typeof cleanEnv !== "object" || Array.isArray(cleanEnv)) {
    throw new Error("signer-config: env must be an object (an explicit allowlist — default {} is a fully empty child environment)");
  }
  for (const [k, v] of Object.entries(cleanEnv)) {
    if (typeof v !== "string") throw new Error(`signer-config: env["${k}"] must be a string`);
  }
  if (algo !== "ed25519") {
    throw new Error('signer-config: algo must be "ed25519" — the only algorithm supported at launch');
  }
  if (typeof publicKeyDerBase64 !== "string" || publicKeyDerBase64.length === 0) {
    throw new Error("signer-config: publicKeyDerBase64 must be a non-empty base64 string (SPKI DER)");
  }
  let publicKeyDer;
  try {
    publicKeyDer = Buffer.from(publicKeyDerBase64, "base64");
  } catch {
    throw new Error("signer-config: publicKeyDerBase64 did not decode as base64");
  }
  if (publicKeyDer.length === 0) throw new Error("signer-config: publicKeyDerBase64 decoded to zero bytes");

  const cleanTimeoutMs = timeoutMs ?? 10_000;
  if (!Number.isInteger(cleanTimeoutMs) || cleanTimeoutMs <= 0 || cleanTimeoutMs > 120_000) {
    throw new Error("signer-config: timeoutMs must be a positive integer, max 120000 (120s)");
  }
  const cleanMaxOutputBytes = maxOutputBytes ?? 8192;
  if (!Number.isInteger(cleanMaxOutputBytes) || cleanMaxOutputBytes <= 0 || cleanMaxOutputBytes > 65536) {
    throw new Error("signer-config: maxOutputBytes must be a positive integer, max 65536 (64KiB)");
  }

  return {
    command: command.trim(),
    args: cleanArgs,
    env: cleanEnv,
    algo,
    publicKeyDerBase64,
    timeoutMs: cleanTimeoutMs,
    maxOutputBytes: cleanMaxOutputBytes,
  };
}

export function loadSignerConfig() {
  const path = statePath(CONFIG_FILE);
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

// Callers MUST have already redeemed a signer-config consent ticket
// (token.mjs createSignerConfigTicket/redeemSignerConfigTicket) before
// calling this — enforced in server.mjs's route handler, not here, so this
// function stays a pure "validate + persist" unit that's simple to test on
// its own without threading ticket state through it.
export function writeSignerConfig(input) {
  const clean = validateSignerConfig(input);
  const path = statePath(CONFIG_FILE);
  writeFileSync(path, JSON.stringify({ ...clean, updatedAt: new Date().toISOString() }, null, 2) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return clean;
}

// Safe-to-return-to-the-browser view: everything is non-secret (see header),
// so this is currently identical to loadSignerConfig — kept as a separate
// name so a future field that IS sensitive (e.g. a per-call passphrase for
// the signer binary itself) has an obvious place to redact without a caller
// needing to change which function it calls.
export function publicSignerConfigView() {
  return loadSignerConfig();
}

export { CONFIG_FILE as SIGNER_CONFIG_FILE };
