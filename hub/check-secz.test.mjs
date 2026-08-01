// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// SECZ-PACK-1 (SECURITISATION-WATERFALL-BUILD-SPEC.md §5): exercises `helm
// check` against the REAL vendored art-509-recompute-payment-waterfall kernel
// via the REAL compiled pack (getPack("pack-art-509-recompute-payment-waterfall"))
// — no mock kernel, no hand-built arithmetic. Fixtures are the kernel's own
// conformance vectors (hub/vendored/ocg/kernels/fixtures/art-509-recompute-
// payment-waterfall.fixtures.json), split into the { inputs, asserted } shape
// helm check's CLI contract expects, exactly the pattern check.test.mjs
// already proved for the bordereau pack (HELMCHECK-BUILD-1) — no second test
// harness, no second diff implementation.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const TMP = mkdtempSync(join(tmpdir(), "helm-check-secz-test-"));
process.env.HELM_HOME = TMP;

const { runCheck, EXIT } = await import("./check.mjs");
const { getPack } = await import("./packs.mjs");

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = JSON.parse(
  readFileSync(join(HERE, "vendored", "ocg", "kernels", "fixtures", "art-509-recompute-payment-waterfall.fixtures.json"), "utf8")
);
const PACK_ID = "pack-art-509-recompute-payment-waterfall";
const ART510_PACK_ID = "pack-art-510-build-art5-diligence-evidence";

function vector(name) {
  const v = FIXTURES.vectors.find((v) => v.name === name);
  assert.ok(v, `fixture vector "${name}" not found`);
  return v;
}

function inputFileFor(vectorName) {
  const pp = { ...vector(vectorName).policy_parameters };
  const asserted = pp.asserted_allocations;
  delete pp.asserted_allocations;
  const body = { inputs: pp };
  if (asserted !== undefined) body.asserted = asserted;
  return JSON.stringify(body);
}

test("helm check (art-509): exit 0 — recomputed matches every asserted allocation", async () => {
  const inputFile = inputFileFor("matches-asserted-report-with-funds-exhaust");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.MATCH);
  assert.equal(result.report.result, "match");
  assert.ok(result.report.fields.length > 0);
  assert.ok(result.report.fields.every((f) => f.match === true));
});

test("helm check (art-509): exit 1 — recomputed differs from asserted, reported as a finding not an error", async () => {
  const inputFile = inputFileFor("differs-from-asserted-report");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.DIFFERS);
  assert.equal(result.report.result, "differs");
  assert.ok(result.report.fields.some((f) => f.match === false));
});

test("helm check (art-509): exit 2 — no asserted key, recompute-only, distinct from match", async () => {
  const v = vector("recompute-only-no-asserted-allocations");
  const inputFile = JSON.stringify({ inputs: v.policy_parameters });
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.NO_ASSERTION);
  assert.equal(result.report.result, "no_assertion");
  assert.notEqual(result.exitCode, EXIT.MATCH);
});

test("helm check (art-509): exit 3 — input_file missing a usable `inputs` object", async () => {
  const result = await runCheck({ packId: PACK_ID, inputFile: JSON.stringify({ foo: "bar" }), noAnchor: true });
  assert.equal(result.exitCode, EXIT.INSUFFICIENT_INPUT);
  assert.ok(!result.report);
});

test("helm check (art-509): exit 4 — unparsable input_file is a usage error", async () => {
  const result = await runCheck({ packId: PACK_ID, inputFile: "{not valid json", noAnchor: true });
  assert.equal(result.exitCode, EXIT.USAGE_ERROR);
});

test("helm check (art-509): finite gate — zero available funds resolves to a defined result, never a crash", async () => {
  const inputFile = inputFileFor("zero-available-funds-finite-gate");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.ok([EXIT.MATCH, EXIT.DIFFERS, EXIT.NO_ASSERTION].includes(result.exitCode));
  assert.ok(Number.isFinite(result.exitCode));
});

test("helm check (art-509): --no-anchor ships a bundle with zero anchors_ref entries", async () => {
  const inputFile = inputFileFor("matches-asserted-report-with-funds-exhaust");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.deepEqual(result.bundle.manifest.predicate.anchors_ref, []);
  assert.equal(result.bundle.manifest.predicate.entries[0].kind, "check_result");
  assert.equal(result.bundle.manifest.predicate.entries[0].trust_label, "kernel_verified");
});

test("helm check (art-509): the sealed bundle verifies offline with zero network access", async () => {
  const { verifyBundle } = await import("./bundle.mjs");
  const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
  const inputFile = inputFileFor("matches-asserted-report-with-funds-exhaust");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  const publicKeys = publicKeysOf(loadOrCreateKeys());
  const verified = await verifyBundle(result.bundle, publicKeys);
  assert.equal(verified.valid, true);
  assert.deepEqual(verified.reasons, []);
});

// NO-DUPLICATED-MATH: this file adds no arithmetic identifiers of its own —
// it only supplies fixtures and reads check.mjs's classification of fields
// the kernel already computed. The negative assertion in check.test.mjs
// already proves check.mjs carries no footing/money arithmetic; this test
// proves the art-509 CHECK_ADAPTERS entry is data (an object literal), not a
// function, so no pack-specific diff code was added alongside it.
test("helm check: pack-art-509 adapter is declarative data, not a second diff implementation", () => {
  const src = readFileSync(join(HERE, "check.mjs"), "utf8");
  const block = src.slice(src.indexOf("const CHECK_ADAPTERS"), src.indexOf("function currenciesOf"));
  assert.match(block, /"pack-art-509-recompute-payment-waterfall":\s*\{/);
  assert.ok(!/function/.test(block), "CHECK_ADAPTERS block must contain no function definitions");
});

// SECZ-PACK-1 done-criterion: both kernels resolve via getPack and run
// through the existing kernel-runner path (art-510 is a compiled pack even
// though it is not wired into helm check's CHECK_ADAPTERS — see check.mjs's
// comment on the entry above for why).
test("both SECZ-PACK-1 packs resolve via getPack — art-509 (checkable) and art-510 (pack-only)", () => {
  const pack509 = getPack(PACK_ID);
  const pack510 = getPack(ART510_PACK_ID);
  assert.ok(pack509, "pack-art-509-recompute-payment-waterfall must resolve via getPack");
  assert.equal(pack509.manifest.nodes[0].kernel_id, "art-509-recompute-payment-waterfall");
  assert.ok(pack510, "pack-art-510-build-art5-diligence-evidence must resolve via getPack");
  assert.equal(pack510.manifest.nodes[0].kernel_id, "art-510-build-art5-diligence-evidence");
});

test("helm check: pack-art-510 is not registered in CHECK_ADAPTERS (no self-diff surface in its kernel)", async () => {
  const result = await runCheck({ packId: ART510_PACK_ID, inputFile: JSON.stringify({ inputs: {} }), noAnchor: true });
  assert.equal(result.exitCode, EXIT.USAGE_ERROR);
});
