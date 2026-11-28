// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// RISC0-310-R4-VENDOR-HELM-1: helm's vendored receipt verifier carries BOTH risc0 constant sets
// (3.0.x legacy + 3.1.0 current). scripts/test.mjs skips hub/vendored, so the dual-form contract
// is pinned here against the vendored bytes (never re-typed constants).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifySeal,
  verifySealReport,
  sealParameterSet,
  LEGACY_IMAGE_IDS,
  CURRENT_IMAGE_IDS,
} from "./vendored/ocg/kernels/_computeproof.mjs";

const KERNELS = join(dirname(fileURLToPath(import.meta.url)), "vendored/ocg/kernels/fixtures");
const load = (p) => JSON.parse(readFileSync(join(KERNELS, p), "utf8"));
const PILOT = load("compute-proof-310/art-313-traiga-exposure-assessor.receipt.json");
const OLD = load("compute-proof/art-04-agent-identity-attestation-checker.receipt.json");

function flipSeal(cp) {
  const b = Uint8Array.from(atob(cp.seal), (ch) => ch.charCodeAt(0));
  b[200] ^= 0x01;
  return { ...cp, seal: btoa(String.fromCharCode(...b)) };
}

test("allowlists are closed: 7 legacy ids, 8 current ids, disjoint", () => {
  assert.equal(LEGACY_IMAGE_IDS.length, 7);
  assert.equal(CURRENT_IMAGE_IDS.length, 8);
  assert.equal(LEGACY_IMAGE_IDS.filter((i) => CURRENT_IMAGE_IDS.includes(i)).length, 0);
});

test("art-313 pilot receipt reads current", () => {
  assert.equal(verifySealReport(PILOT), "current");
  assert.equal(verifySeal(PILOT), true);
});

test("an old (3.0.x) receipt reads legacy", () => {
  assert.equal(sealParameterSet(OLD.imageId), "legacy");
  assert.equal(verifySealReport(OLD), "legacy");
  assert.equal(verifySeal(OLD), true);
});

test("a tampered journal reads invalid", () => {
  const t = structuredClone(PILOT);
  t.journal.output = { ...t.journal.output, __tamper_probe: true };
  assert.equal(verifySealReport(t), "invalid");
  assert.equal(verifySeal(t), false);
  assert.equal(verifySealReport(flipSeal(PILOT)), "invalid");
});

test("an imageId in neither list reads invalid", () => {
  const stranger = { ...PILOT, imageId: "sha256:" + "ab".repeat(32) };
  assert.equal(sealParameterSet(stranger.imageId), null);
  assert.equal(verifySealReport(stranger), "invalid");
  assert.equal(verifySeal(stranger), false);
});
