// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELMCHECK-BUILD-1: exercises all six `helm check` exit codes against the
// REAL vendored art-508-recompute-bordereau kernel via the REAL compiled pack
// (getPack("pack-art-508-recompute-bordereau")) — no mock kernel, no
// hand-built arithmetic. Fixtures are the kernel's own conformance vectors
// (hub/vendored/ocg/kernels/fixtures/art-508-recompute-bordereau.fixtures.json),
// split into the { inputs, asserted } shape helm check's CLI contract expects.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const TMP = mkdtempSync(join(tmpdir(), "helm-check-test-"));
process.env.HELM_HOME = TMP;

const { runCheck, EXIT } = await import("./check.mjs");

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = JSON.parse(
  readFileSync(join(HERE, "vendored", "ocg", "kernels", "fixtures", "art-508-recompute-bordereau.fixtures.json"), "utf8")
);
const PACK_ID = "pack-art-508-recompute-bordereau";

function vector(name) {
  const v = FIXTURES.vectors.find((v) => v.name === name);
  assert.ok(v, `fixture vector "${name}" not found`);
  return v;
}

function inputFileFor(vectorName) {
  const pp = { ...vector(vectorName).policy_parameters };
  const asserted = pp.asserted_totals;
  delete pp.asserted_totals;
  const body = { inputs: pp };
  if (asserted !== undefined) body.asserted = asserted;
  return JSON.stringify(body);
}

test("helm check: exit 0 — recomputed matches every asserted figure", async () => {
  const inputFile = inputFileFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.MATCH);
  assert.equal(result.report.result, "match");
  assert.ok(result.report.fields.length > 0);
  assert.ok(result.report.fields.every((f) => f.match === true));
});

test("helm check: exit 1 — recomputed differs from asserted, reported as a finding not an error", async () => {
  const inputFile = inputFileFor("totals-differ-reported-as-a-finding");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.DIFFERS);
  assert.equal(result.report.result, "differs");
  assert.ok(result.report.fields.some((f) => f.match === false));
});

test("helm check: exit 2 — no asserted key, recompute-only, distinct from match", async () => {
  const v = vector("recompute-only-is-its-own-state");
  const inputFile = JSON.stringify({ inputs: v.policy_parameters });
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.NO_ASSERTION);
  assert.equal(result.report.result, "no_assertion");
  assert.notEqual(result.exitCode, EXIT.MATCH);
});

test("helm check: exit 3 — input_file missing a usable `inputs` object", async () => {
  const result = await runCheck({ packId: PACK_ID, inputFile: JSON.stringify({ foo: "bar" }), noAnchor: true });
  assert.equal(result.exitCode, EXIT.INSUFFICIENT_INPUT);
  assert.ok(!result.report);
});

test("helm check: exit 4 — unknown pack_id is a usage error, distinct from every other code", async () => {
  const result = await runCheck({ packId: "pack-does-not-exist", inputFile: "{}", noAnchor: true });
  assert.equal(result.exitCode, EXIT.USAGE_ERROR);
});

test("helm check: exit 4 — unparsable input_file is a usage error", async () => {
  const result = await runCheck({ packId: PACK_ID, inputFile: "{not valid json", noAnchor: true });
  assert.equal(result.exitCode, EXIT.USAGE_ERROR);
});

test("helm check: exit 5 — asserted currency shares no overlap with the recomputed rows (scope, not a number mismatch)", async () => {
  const v = vector("matches-asserted-totals-multi-currency-with-unmapped-personal-columns");
  const pp = { ...v.policy_parameters };
  delete pp.asserted_totals;
  const inputFile = JSON.stringify({ inputs: pp, asserted: [{ currency: "USD", gross_premium: "1.00" }] });
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.equal(result.exitCode, EXIT.SCOPE_DISAGREEMENT);
  assert.equal(result.report.result, "scope_mismatch");
  assert.notEqual(result.exitCode, EXIT.DIFFERS);
});

test("helm check: all six exit codes are pairwise distinct", () => {
  const codes = Object.values(EXIT);
  assert.equal(new Set(codes).size, codes.length);
});

test("helm check: --no-anchor ships a bundle with zero anchors_ref entries", async () => {
  const inputFile = inputFileFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  assert.deepEqual(result.bundle.manifest.predicate.anchors_ref, []);
  assert.equal(result.bundle.manifest.predicate.entries[0].kind, "check_result");
  assert.equal(result.bundle.manifest.predicate.entries[0].trust_label, "kernel_verified");
});

test("helm check: the sealed bundle verifies offline with zero network access", async () => {
  const { verifyBundle } = await import("./bundle.mjs");
  const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
  const inputFile = inputFileFor("matches-asserted-totals-multi-currency-with-unmapped-personal-columns");
  const result = await runCheck({ packId: PACK_ID, inputFile, noAnchor: true });
  const publicKeys = publicKeysOf(loadOrCreateKeys());
  const verified = await verifyBundle(result.bundle, publicKeys);
  assert.equal(verified.valid, true);
  assert.deepEqual(verified.reasons, []);
});

// NO-DUPLICATED-MATH PROOF (row done-criterion: "pack uses the SITE kernel
// via getPack/kernel-runner, zero duplicated math, proven by diffing the
// arithmetic source"). check.mjs must import the real execution path and
// must not define any footing/money arithmetic of its own — it only reads
// fields the kernel already computed (output_payload.comparison_state,
// output_payload.diff) and classifies them into an exit code.
test("helm check: check.mjs reuses kernel-runner's runKernelNode — no second execution path, no duplicated arithmetic", () => {
  const src = readFileSync(join(HERE, "check.mjs"), "utf8");
  assert.match(src, /import\s*\{[^}]*runKernelNode[^}]*\}\s*from\s*"\.\/kernel-runner\.mjs"/);
  // Money-measure identifiers only the kernel's own footing logic owns —
  // their presence here would mean this file reimplemented the arithmetic.
  for (const forbidden of ["MONEY_MEASURES", "DEDUCTION_MEASURES", "gross_premium_minor_units", "parseAmount("]) {
    assert.ok(!src.includes(forbidden), `check.mjs must not reimplement kernel arithmetic (found "${forbidden}")`);
  }
});

test("helm check: no daemon, no server import — a one-shot process", () => {
  const src = readFileSync(join(HERE, "check.mjs"), "utf8");
  assert.ok(!src.includes("./server.mjs"));
  assert.ok(!src.includes("createServer"));
  assert.ok(!src.includes("listen("));
});
