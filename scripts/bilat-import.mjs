#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// BILAT-H2H-CLI-1: `helmd bilat-import` (BILAT-H2H-BUILD-SPEC.md §2.2, §5) —
// the CLI half of hub/h2h-envelope.mjs's importH2HEnvelope(). Verifies a
// received .helm-envelope file against a counterparty's public keys (handed
// over out of band per §2.2 — this command holds no peer directory of its
// own) and, on success, writes the recovered payload to disk. No network
// call, no listener: reads two files, writes zero or one file, exits.
//
// Fails closed exactly per spec §5: an unrecognized version, an unrecognized
// payload_type, or a bad signature all produce ONE plain-language message on
// stderr and a nonzero exit — never a partial write of --out.
import { statSync, readFileSync, writeFileSync } from "node:fs";
import { createPublicKey } from "node:crypto";
import { pathToFileURL } from "node:url";
import { importH2HEnvelope } from "../hub/h2h-envelope.mjs";

// Same rationale as scripts/verify.mjs — reject a hostile/corrupt file by
// size before JSON.parse ever runs.
export const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB
export const EXIT = { OK: 0, REJECTED: 1, USAGE_ERROR: 2 };

function usage() {
  console.error(`usage: helmd bilat-import <envelope.json> --peer-keys <peerPublicKeys.json> [--out <payload.json>] [--strict] [--json]

Verifies a received Helm-to-Helm exchange envelope against a counterparty's
public keys (get these from the sender out of band, e.g. their own
"helmd bilat-pubkey" output — Helm keeps no peer directory of its own,
BILAT-H2H-BUILD-SPEC.md §2.2). On success, writes the recovered payload to
--out if given.

--strict requires BOTH the Ed25519 and ML-DSA-44 signatures present and
valid (default: Ed25519 MUST, ML-DSA-44 SHOULD — see hub/envelope.mjs).

Exit codes:
  0  envelope verified and accepted; payload written to --out if given
  1  envelope REJECTED (bad signature, unrecognized version, unrecognized
     payload_type, missing sender_org_id) — fails closed, no partial write
  2  usage error (missing flag, unreadable/oversized/malformed input file)
     — verification was never attempted`);
}

export function readAndParseCapped(path, label) {
  let size;
  try {
    size = statSync(path).size;
  } catch (err) {
    throw { usageError: `cannot read ${label} "${path}": ${String(err?.message || err)}` };
  }
  if (size > MAX_FILE_BYTES) {
    throw { usageError: `${label} "${path}" is ${size} bytes, exceeding the ${MAX_FILE_BYTES}-byte cap — rejected before parsing` };
  }
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw { usageError: `cannot read ${label} "${path}": ${String(err?.message || err)}` };
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw { usageError: `${label} "${path}" is not valid JSON: ${String(err?.message || err)}` };
  }
}

// peerKeysJson = { ed25519SpkiB64, mldsa44B64 } — same shareable shape
// bilat-pubkey.mjs prints. Converts to the { ed25519: KeyObject,
// mldsa44: Uint8Array } shape hub/envelope.mjs's verifyEnvelope() requires.
export function validatePeerKeysShape(peerKeys) {
  if (!peerKeys || typeof peerKeys !== "object") return "peer-keys file must be a JSON object";
  for (const field of ["ed25519SpkiB64", "mldsa44B64"]) {
    const v = peerKeys[field];
    if (typeof v !== "string" || v.length === 0) return `peer-keys file missing required non-empty string field "${field}"`;
  }
  return null;
}

export function toVerifierPublicKeys(peerKeys) {
  return {
    ed25519: createPublicKey({ key: Buffer.from(peerKeys.ed25519SpkiB64, "base64"), format: "der", type: "spki" }),
    mldsa44: new Uint8Array(Buffer.from(peerKeys.mldsa44B64, "base64")),
  };
}

export function parseArgs(rawArgs) {
  const flags = new Set();
  const positional = [];
  let peerKeysPath, outPath;
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === "--peer-keys") { peerKeysPath = rawArgs[++i]; continue; }
    if (a === "--out") { outPath = rawArgs[++i]; continue; }
    if (a.startsWith("--")) { flags.add(a); continue; }
    positional.push(a);
  }
  return { envelopePath: positional[0], peerKeysPath, outPath, strict: flags.has("--strict"), jsonMode: flags.has("--json") };
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes("-h") || rawArgs.includes("--help")) {
    usage();
    process.exit(0);
  }
  const { envelopePath, peerKeysPath, outPath, strict, jsonMode } = parseArgs(rawArgs);

  if (!envelopePath || !peerKeysPath) {
    usage();
    process.exit(EXIT.USAGE_ERROR);
  }

  let envelope, peerKeysJson;
  try {
    envelope = readAndParseCapped(envelopePath, "envelope");
    peerKeysJson = readAndParseCapped(peerKeysPath, "peer-keys file");
  } catch (err) {
    if (err && err.usageError) {
      console.error(`helmd bilat-import: ${err.usageError}`);
      process.exit(EXIT.USAGE_ERROR);
    }
    throw err;
  }

  const shapeErr = validatePeerKeysShape(peerKeysJson);
  if (shapeErr) {
    console.error(`helmd bilat-import: ${shapeErr}`);
    process.exit(EXIT.USAGE_ERROR);
  }

  let peerPublicKeys;
  try {
    peerPublicKeys = toVerifierPublicKeys(peerKeysJson);
  } catch (err) {
    console.error(`helmd bilat-import: peer-keys file is malformed: ${String(err?.message || err)}`);
    process.exit(EXIT.USAGE_ERROR);
  }

  const result = importH2HEnvelope(envelope, peerPublicKeys, { strict });

  if (!result.ok) {
    if (jsonMode) {
      console.log(JSON.stringify({ ok: false, reason: result.reason, message: result.message }));
    } else {
      console.error(`helmd bilat-import: ${result.message}`);
    }
    process.exit(EXIT.REJECTED);
  }

  if (outPath) {
    writeFileSync(outPath, JSON.stringify(result.payload, null, 2) + "\n", { mode: 0o600 });
  }

  if (jsonMode) {
    console.log(JSON.stringify({ ok: true, senderOrgId: result.senderOrgId, payloadType: result.payloadType, out: outPath ?? null }));
  } else {
    console.log(`helmd bilat-import: ${envelopePath}`);
    console.log(`  result: ACCEPTED`);
    console.log(`  sender_org_id: ${result.senderOrgId}`);
    console.log(`  payload_type: ${result.payloadType}`);
    if (outPath) console.log(`  payload written to: ${outPath}`);
  }
  process.exit(EXIT.OK);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
