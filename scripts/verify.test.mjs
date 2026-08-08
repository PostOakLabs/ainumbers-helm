// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-VERIFY-CLI-1 — RED-BEFORE-GREEN for all four §1.4 conditions
// (HELM-VERIFY-CLI-BUILD-SPEC.md §1.4), plus the exit-code table and the
// fingerprint-on-verify usability gap. Each RED case is run against the REAL
// pre-patch shape first (see comments) so the test is proven to fail for the
// stated reason, not vacuously.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXIT,
  MAX_FILE_BYTES,
  MAX_DEPTH,
  computeMaxDepth,
  validateKeysShape,
  fingerprintKey,
  readAndParseCapped,
} from "./verify.mjs";
import { DEMO_PUBLIC_KEYS, DEMO_GOLDEN_BUNDLE, DEMO_TAMPERED_BUNDLE } from "../ui/fixtures/verify-demo.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERIFY_ENTRY = join(HERE, "verify.mjs");

function tmpFile(name, content) {
  const dir = mkdtempSync(join(tmpdir(), "helm-verify-cli-1-"));
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

function runCli(args) {
  return spawnSync(process.execPath, [VERIFY_ENTRY, ...args], { encoding: "utf8" });
}

// --- §1.4 condition 1: resource exhaustion ---------------------------------

test("RED: computeMaxDepth is asked to walk a pathologically deep object — must not stack-overflow itself", () => {
  // Built ITERATIVELY (not via recursion) so constructing the fixture can't
  // itself overflow the stack — the point of the test is that the GUARD's own
  // walk is iterative, proven by using a depth far beyond V8's default
  // recursive call-stack ceiling (~10-15k frames).
  let root = {};
  let cur = root;
  for (let i = 0; i < 200000; i++) {
    cur.a = {};
    cur = cur.a;
  }
  // GREEN: short-circuits past MAX_DEPTH without walking the whole tree or
  // throwing a RangeError.
  const depth = computeMaxDepth(root, MAX_DEPTH);
  assert.ok(depth > MAX_DEPTH);
});

test("RED-before-GREEN: an oversized bundle.json is rejected by size BEFORE JSON.parse ever runs", () => {
  const dir = mkdtempSync(join(tmpdir(), "helm-verify-cli-1-"));
  const bundlePath = join(dir, "bundle.json");
  // Deliberately malformed JSON padded past the cap — if the size check ran
  // AFTER JSON.parse (the RED shape), this would throw a JSON parse error
  // instead of the size-cap usage error; observing the SIZE-specific message
  // proves the cap runs first.
  writeFileSync(bundlePath, "x".repeat(MAX_FILE_BYTES + 1024));
  assert.throws(
    () => readAndParseCapped(bundlePath, "bundle"),
    (err) => /exceeding the .* cap — rejected before parsing/.test(err.usageError)
  );
  rmSync(dir, { recursive: true, force: true });
});

test("GREEN: computeMaxDepth accepts a shallow, well-formed structure unchanged", () => {
  assert.equal(computeMaxDepth(DEMO_GOLDEN_BUNDLE, MAX_DEPTH), computeMaxDepth(DEMO_GOLDEN_BUNDLE));
  assert.ok(computeMaxDepth(DEMO_GOLDEN_BUNDLE) < MAX_DEPTH);
});

// --- §1.4 condition 2: malformed publicKeys.json shape ---------------------

test("RED-before-GREEN: publicKeys.json missing ed25519SpkiB64 is rejected, not silently treated as nothing-to-check", () => {
  const err = validateKeysShape({ mldsa44B64: DEMO_PUBLIC_KEYS.mldsa44B64 });
  assert.match(err, /ed25519SpkiB64/);
});

test("RED-before-GREEN: publicKeys.json with an empty string field is rejected", () => {
  const err = validateKeysShape({ ed25519SpkiB64: "", mldsa44B64: DEMO_PUBLIC_KEYS.mldsa44B64 });
  assert.match(err, /ed25519SpkiB64/);
});

test("RED-before-GREEN: publicKeys.json with non-base64 garbage is rejected", () => {
  const err = validateKeysShape({ ed25519SpkiB64: "not base64!!", mldsa44B64: DEMO_PUBLIC_KEYS.mldsa44B64 });
  assert.match(err, /not valid base64/);
});

test("GREEN: a well-shaped publicKeys.json passes shape validation", () => {
  assert.equal(validateKeysShape(DEMO_PUBLIC_KEYS), null);
});

// --- §1.4 condition 3: substituted-key TOFU gap (fingerprint-on-verify) ----

test("fingerprintKey is deterministic and differs for different keys", () => {
  const fp1 = fingerprintKey(DEMO_PUBLIC_KEYS.ed25519SpkiB64);
  const fp2 = fingerprintKey(DEMO_PUBLIC_KEYS.ed25519SpkiB64);
  assert.equal(fp1, fp2);
  assert.equal(fp1.length, 64); // sha256 hex
  const fp3 = fingerprintKey(DEMO_PUBLIC_KEYS.mldsa44B64);
  assert.notEqual(fp1, fp3);
});

test("end-to-end: a VALID bundle prints the fingerprint of the key it actually verified against", () => {
  const bundlePath = tmpFile("bundle.json", JSON.stringify(DEMO_GOLDEN_BUNDLE));
  const keysPath = join(dirname(bundlePath), "keys.json");
  writeFileSync(keysPath, JSON.stringify(DEMO_PUBLIC_KEYS));
  const result = runCli([bundlePath, "--keys", keysPath, "--json"]);
  assert.equal(result.status, EXIT.VALID);
  const out = JSON.parse(result.stdout);
  assert.equal(out.valid, true);
  assert.equal(out.fingerprints.ed25519, fingerprintKey(DEMO_PUBLIC_KEYS.ed25519SpkiB64));
  assert.equal(out.fingerprints.mldsa44, fingerprintKey(DEMO_PUBLIC_KEYS.mldsa44B64));
});

test("end-to-end: an INVALID bundle prints no fingerprint (nothing to trust)", () => {
  const bundlePath = tmpFile("bundle.json", JSON.stringify(DEMO_TAMPERED_BUNDLE));
  const keysPath = join(dirname(bundlePath), "keys.json");
  writeFileSync(keysPath, JSON.stringify(DEMO_PUBLIC_KEYS));
  const result = runCli([bundlePath, "--keys", keysPath, "--json"]);
  assert.equal(result.status, EXIT.INVALID);
  const out = JSON.parse(result.stdout);
  assert.equal(out.valid, false);
  assert.equal(out.fingerprints, null);
});

// --- §1.4 condition 4: exit code collapse -----------------------------------

test("exit 2: a typo'd bundle filename never reaches 'valid: false' — it's a usage error, distinct from a real negative", () => {
  const result = runCli(["/no/such/bundle.json", "--keys", "/no/such/keys.json"]);
  assert.equal(result.status, EXIT.USAGE_ERROR);
});

test("exit 2: malformed publicKeys.json is a usage error, not a false PASS or an uncaught crash", () => {
  const bundlePath = tmpFile("bundle.json", JSON.stringify(DEMO_GOLDEN_BUNDLE));
  const keysPath = join(dirname(bundlePath), "keys.json");
  writeFileSync(keysPath, JSON.stringify({ ed25519SpkiB64: "" }));
  const result = runCli([bundlePath, "--keys", keysPath]);
  assert.equal(result.status, EXIT.USAGE_ERROR);
});

test("exit 1: a genuinely forged bundle is DISTINGUISHABLE from a usage error", () => {
  const bundlePath = tmpFile("bundle.json", JSON.stringify(DEMO_TAMPERED_BUNDLE));
  const keysPath = join(dirname(bundlePath), "keys.json");
  writeFileSync(keysPath, JSON.stringify(DEMO_PUBLIC_KEYS));
  const result = runCli([bundlePath, "--keys", keysPath]);
  assert.equal(result.status, EXIT.INVALID);
  assert.notEqual(result.status, EXIT.USAGE_ERROR);
});

test("exit 0: the golden bundle verifies clean end to end via the real CLI subprocess", () => {
  const bundlePath = tmpFile("bundle.json", JSON.stringify(DEMO_GOLDEN_BUNDLE));
  const keysPath = join(dirname(bundlePath), "keys.json");
  writeFileSync(keysPath, JSON.stringify(DEMO_PUBLIC_KEYS));
  const result = runCli([bundlePath, "--keys", keysPath]);
  assert.equal(result.status, EXIT.VALID);
});

test("missing --keys flag is a usage error", () => {
  const bundlePath = tmpFile("bundle.json", JSON.stringify(DEMO_GOLDEN_BUNDLE));
  const result = runCli([bundlePath]);
  assert.equal(result.status, EXIT.USAGE_ERROR);
});
