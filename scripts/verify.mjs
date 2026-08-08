#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-VERIFY-CLI-1: `helmd verify <bundle.json> --keys <publicKeys.json>
// [--json] [--anchor-full]` — the missing other half of the check/verify
// round-trip (HELM-VERIFY-CLI-BUILD-SPEC.md §1). Calls
// ui/lib/verify-bundle.mjs's verifyBundle() ONLY — never hub/bundle.mjs's
// server-side copy (§1.1). Thin wrapper in the same shape as scripts/check.mjs:
// parse argv by hand, readFileSync + JSON.parse both inputs, call verifyBundle,
// map result to exit code and stdout, done. Guard helpers below are exported
// so the RED-BEFORE-GREEN test suite can unit-test each one directly, not
// only through a full child-process spawn.
import { readFileSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { verifyBundle } from "../ui/lib/verify-bundle.mjs";
import { base64ToBytes } from "../ui/lib/verify-envelope.mjs";
import { verifyAnchorFull } from "../ui/lib/verify-bundle.mjs";

// §1.4 condition 1 — resource exhaustion. Numbers are generous for a real
// evidence bundle (documented in --help) but bounded so a hostile input fails
// closed instead of exhausting memory/stack before verification even runs.
export const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50MB
export const MAX_DEPTH = 500;

export const EXIT = { VALID: 0, INVALID: 1, USAGE_ERROR: 2 };

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

function usage() {
  console.error(`usage: helmd verify <bundle.json> --keys <publicKeys.json> [--json] [--anchor-full]

Verifies an evidence bundle produced by "helmd check --out bundle.json"
entirely offline, against a caller-supplied public-key file (Helm has no key
registry by design — publicKeys.json travels alongside bundle.json out of
band, same channel that already carries the bundle).

Caps: bundle.json and publicKeys.json are each rejected above ${MAX_FILE_BYTES / (1024 * 1024)}MB
(before JSON.parse); a manifest/entry object nested deeper than ${MAX_DEPTH}
levels is rejected before verification is attempted.

Exit codes:
  0  bundle cryptographically valid
  1  bundle verification FAILED (envelope/digest/schema/redaction mismatch)
  2  usage error (file not found, malformed JSON, malformed publicKeys.json,
     missing required flag) — verification was never attempted

Zero-network by default. --anchor-full opts into the deeper RFC-3161
chain-of-trust check (pinned local root set, still no network call) on top of
the base structural verify.`);
}

// Reads a file and enforces the §1.4 condition 1 size cap BEFORE JSON.parse
// ever sees the bytes. Returns the parsed value or throws {usageError: msg}.
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

// §1.4 condition 1 (depth half) — an ITERATIVE (explicit-stack) walk so the
// guard itself cannot be tripped into a stack overflow by the very input it's
// meant to reject. Returns the max nesting depth encountered, short-circuiting
// as soon as it exceeds maxDepth (no need to walk the rest of a hostile tree).
export function computeMaxDepth(value, maxDepth = Infinity) {
  let max = 0;
  const stack = [[value, 0]];
  while (stack.length) {
    const [node, depth] = stack.pop();
    if (depth > max) max = depth;
    if (max > maxDepth) return max;
    if (Array.isArray(node)) {
      for (const v of node) stack.push([v, depth + 1]);
    } else if (node && typeof node === "object") {
      for (const v of Object.values(node)) stack.push([v, depth + 1]);
    }
  }
  return max;
}

// §1.4 condition 2 — publicKeys.json shape validation BEFORE calling
// verifyBundle. A bundle must never come back "valid" because the trust
// input was empty, absent, or malformed — that failure mode is worse than an
// uncaught TypeError, it silently under-verifies.
export function validateKeysShape(publicKeys) {
  if (!publicKeys || typeof publicKeys !== "object") return "publicKeys.json must be a JSON object";
  for (const field of ["ed25519SpkiB64", "mldsa44B64"]) {
    const v = publicKeys[field];
    if (typeof v !== "string" || v.length === 0) return `publicKeys.json missing required non-empty string field "${field}"`;
    if (!BASE64_RE.test(v)) return `publicKeys.json field "${field}" is not valid base64`;
  }
  return null;
}

// §1.4 condition 3 — fingerprint-on-verify. A caller with an out-of-band
// confirmed fingerprint can catch a substituted-but-self-consistent key file;
// this does not change the cryptography, it closes the usability gap.
export function fingerprintKey(base64Value) {
  return createHash("sha256").update(base64ToBytes(base64Value)).digest("hex");
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes("-h") || rawArgs.includes("--help")) {
    usage();
    process.exit(0);
  }
  const jsonMode = rawArgs.includes("--json");
  const anchorFull = rawArgs.includes("--anchor-full");
  let keysPath;
  const positional = [];
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === "--keys") { keysPath = rawArgs[++i]; continue; }
    if (a.startsWith("--")) continue;
    positional.push(a);
  }
  const [bundlePath] = positional;

  if (!bundlePath || !keysPath) {
    usage();
    process.exit(EXIT.USAGE_ERROR);
  }

  let bundle, publicKeys;
  try {
    bundle = readAndParseCapped(bundlePath, "bundle");
    publicKeys = readAndParseCapped(keysPath, "publicKeys");
  } catch (err) {
    if (err && err.usageError) {
      console.error(`helmd verify: ${err.usageError}`);
      process.exit(EXIT.USAGE_ERROR);
    }
    throw err;
  }

  const keysErr = validateKeysShape(publicKeys);
  if (keysErr) {
    console.error(`helmd verify: ${keysErr}`);
    process.exit(EXIT.USAGE_ERROR);
  }

  const depth = computeMaxDepth(bundle, MAX_DEPTH);
  if (depth > MAX_DEPTH) {
    console.error(`helmd verify: bundle nesting depth ${depth} exceeds the ${MAX_DEPTH}-level cap — rejected before verification`);
    process.exit(EXIT.USAGE_ERROR);
  }

  const result = await verifyBundle(bundle, publicKeys, { maxDepth: MAX_DEPTH });

  let anchorFullResult;
  if (anchorFull && result.valid) {
    anchorFullResult = [];
    for (const cp of result.detail.checkpoints ?? []) {
      if (!cp.valid || !cp.predicate) continue;
      for (const anchor of cp.predicate.anchors ?? []) {
        anchorFullResult.push({ checkpointSeq: cp.checkpointSeq, ...(await verifyAnchorFull(anchor, cp.predicate.journal_root_digest)) });
      }
    }
  }

  const fingerprints = result.valid
    ? { ed25519: fingerprintKey(publicKeys.ed25519SpkiB64), mldsa44: fingerprintKey(publicKeys.mldsa44B64) }
    : null;

  if (jsonMode) {
    console.log(JSON.stringify({ valid: result.valid, reasons: result.reasons, fingerprints, anchorFull: anchorFullResult ?? null }));
  } else {
    console.log(`helmd verify: ${bundlePath}`);
    console.log(`  result: ${result.valid ? "VALID" : "INVALID"}`);
    if (result.reasons.length) {
      for (const r of result.reasons) console.log(`  reason: ${r}`);
    }
    if (fingerprints) {
      console.log(`  verified against ed25519 fingerprint sha256:${fingerprints.ed25519}`);
      console.log(`  verified against mldsa44 fingerprint  sha256:${fingerprints.mldsa44}`);
    }
    if (anchorFullResult) {
      for (const a of anchorFullResult) {
        console.log(`  anchor-full checkpoint#${a.checkpointSeq}: checked=${a.checked} bound=${a.bound}${a.reason ? ` (${a.reason})` : ""}`);
      }
    }
  }

  process.exit(result.valid ? EXIT.VALID : EXIT.INVALID);
}

// Only run CLI side effects when executed directly (node scripts/verify.mjs
// or via bin/helmd.mjs's spawnSync) — importing this module for its exported
// guard helpers (the test suite's unit-test path) must not touch process.argv
// or call process.exit.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
