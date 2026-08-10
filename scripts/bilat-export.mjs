#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// BILAT-H2H-CLI-1: `helmd bilat-export` (BILAT-H2H-BUILD-SPEC.md §2.2) — the
// CLI half of hub/h2h-envelope.mjs's exportH2HEnvelope(). Wraps an
// already-produced local artifact (a matter-bundle export, a BILAT-CSR
// receipt, a BILAT-COSIGN checkpoint head — whatever the caller already has
// on disk as JSON) in a signed .helm-envelope file addressed to a
// counterparty. No network call: this touches files only, the same
// no-daemon-required shape as scripts/verify.mjs and scripts/check.mjs.
// Transport (email/SFTP/USB/etc.) is the caller's problem after this exits.
import { statSync, readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { loadOrCreateKeys } from "../hub/keys.mjs";
import { exportH2HEnvelope, KNOWN_PAYLOAD_TYPES } from "../hub/h2h-envelope.mjs";

// Same cap rationale as scripts/verify.mjs §1.4 condition 1 — a hostile or
// corrupt payload file fails closed before JSON.parse ever sees the bytes.
export const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB
export const EXIT = { OK: 0, USAGE_ERROR: 2 };

function usage() {
  console.error(`usage: helmd bilat-export --org-id <sender_org_id> --payload-type <type> --payload-file <payload.json> --out <envelope.json> [--json]

Wraps an already-produced local artifact in a signed Helm-to-Helm exchange
envelope (BILAT-H2H-BUILD-SPEC.md §2). --payload-type must be one of:
${[...KNOWN_PAYLOAD_TYPES].join(", ")}

The output file is what actually leaves this machine, by whatever transport
the two orgs already trust (email attachment, SFTP, USB, shared repo — this
command never chooses or touches a transport).

Exit codes:
  0  envelope written to --out
  2  usage error (bad flags, unreadable/oversized/malformed payload file,
     unrecognized --payload-type) — no envelope was written`);
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

export function parseArgs(rawArgs) {
  const flags = new Set();
  let orgId, payloadType, payloadFile, outPath;
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === "--org-id") { orgId = rawArgs[++i]; continue; }
    if (a === "--payload-type") { payloadType = rawArgs[++i]; continue; }
    if (a === "--payload-file") { payloadFile = rawArgs[++i]; continue; }
    if (a === "--out") { outPath = rawArgs[++i]; continue; }
    if (a.startsWith("--")) { flags.add(a); continue; }
  }
  return { orgId, payloadType, payloadFile, outPath, jsonMode: flags.has("--json") };
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes("-h") || rawArgs.includes("--help")) {
    usage();
    process.exit(0);
  }
  const { orgId, payloadType, payloadFile, outPath, jsonMode } = parseArgs(rawArgs);

  if (!orgId || !payloadType || !payloadFile || !outPath) {
    usage();
    process.exit(EXIT.USAGE_ERROR);
  }
  if (!KNOWN_PAYLOAD_TYPES.has(payloadType)) {
    console.error(`helmd bilat-export: unrecognized --payload-type "${payloadType}" (expected one of: ${[...KNOWN_PAYLOAD_TYPES].join(", ")})`);
    process.exit(EXIT.USAGE_ERROR);
  }

  let payload;
  try {
    payload = readAndParseCapped(payloadFile, "payload file");
  } catch (err) {
    if (err && err.usageError) {
      console.error(`helmd bilat-export: ${err.usageError}`);
      process.exit(EXIT.USAGE_ERROR);
    }
    throw err;
  }

  const keys = loadOrCreateKeys();
  const envelope = exportH2HEnvelope({ senderOrgId: orgId, payloadType, payload }, keys);
  writeFileSync(outPath, JSON.stringify(envelope) + "\n", { mode: 0o600 });

  if (jsonMode) {
    console.log(JSON.stringify({ ok: true, out: outPath, senderOrgId: orgId, payloadType }));
  } else {
    console.log(`helmd bilat-export: wrote ${outPath} (payload_type=${payloadType}, sender_org_id=${orgId})`);
  }
  process.exit(EXIT.OK);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
