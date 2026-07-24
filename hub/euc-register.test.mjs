import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { buildKernelCard, buildEucEntry } from "./euc-register.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const KERNEL_CARD_SCHEMA = JSON.parse(readFileSync(join(ROOT, "schema", "kernel_card.schema.json"), "utf8"));
const EUC_ENTRY_SCHEMA = JSON.parse(readFileSync(join(ROOT, "schema", "euc_register_entry.schema.json"), "utf8"));

// pack-aca-226j-response-composer pins 3 kernels, all with vendored fixtures
// — done: "entry + card generate for >=3 kernels/1 workflow, validated
// against fixtures" (board/claimed/HELM-P3-E12.md).
const WORKFLOW_ID = "pack-aca-226j-response-composer";
const KERNEL_IDS = [
  "art-298-aca-affordability-safe-harbor",
  "art-299-aca-esrp-exposure",
  "art-300-aca-226j-response-evidence-pack",
];

test("buildKernelCard: generates a schema-valid card with real vendored fixtures for each kernel", () => {
  for (const kernelId of KERNEL_IDS) {
    const card = buildKernelCard(kernelId, { now: "2026-07-23T00:00:00.000Z" });
    const errs = validate(KERNEL_CARD_SCHEMA, card);
    assert.deepEqual(errs, [], `${kernelId}: card failed schema validation: ${errs.join(", ")}`);
    assert.equal(card.conformance_fixtures_vendored, true, `${kernelId}: expected vendored fixtures`);
    assert.ok(card.test_vectors.length > 0, `${kernelId}: expected at least one test vector`);
    for (const v of card.test_vectors) {
      assert.ok(v.expected_execution_hash, `${kernelId}/${v.name}: missing expected_execution_hash`);
    }
    assert.match(card.kernel_digest, /^sha256:[0-9a-f]{64}$/);
  }
});

test("buildKernelCard: throws on an unknown kernel_id instead of silently returning an empty card", () => {
  assert.throws(() => buildKernelCard("art-does-not-exist"), /unknown kernel_id/);
});

test("buildEucEntry: generates a schema-valid entry pinning all 3 kernels of a real compiled workflow", () => {
  const entry = buildEucEntry(WORKFLOW_ID, {
    owner: "Benefits Compliance Officer",
    controlDescription: "Manually reviewed quarterly against IRS Rev. Proc. thresholds.",
    lastValidated: "2026-07-01",
    now: "2026-07-23T00:00:00.000Z",
  });
  const errs = validate(EUC_ENTRY_SCHEMA, entry);
  assert.deepEqual(errs, [], `entry failed schema validation: ${errs.join(", ")}`);
  assert.equal(entry.workflow_id, WORKFLOW_ID);
  assert.equal(entry.kernels.length, 3);
  assert.deepEqual(entry.kernels.map((k) => k.kernel_id), KERNEL_IDS);
  assert.equal(entry.owner, "Benefits Compliance Officer");
  assert.equal(entry.declared_outputs.length, 1);
  assert.equal(entry.declared_outputs[0].kernel_id, "art-300-aca-226j-response-evidence-pack");
});

test("buildEucEntry: purpose falls back to the pack's outcome when not supplied", () => {
  const entry = buildEucEntry(WORKFLOW_ID, { now: "2026-07-23T00:00:00.000Z" });
  assert.ok(entry.purpose && entry.purpose.length > 0);
  assert.equal(entry.owner, null);
});

test("buildEucEntry: throws on an unknown workflow_id instead of silently returning an empty entry", () => {
  assert.throws(() => buildEucEntry("pack-does-not-exist"), /unknown workflow_id/);
});
