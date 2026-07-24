import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { buildWorkflowExport, parseWorkflowExport } from "./workflow-export.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const SCHEMA = JSON.parse(readFileSync(join(ROOT, "schema", "workflow_export.schema.json"), "utf8"));
const FIXTURES = join(ROOT, "fixtures", "workflow_export");

// Real compiled pack, 3 kernels, no env_overlays — pinned digests in its
// manifest are the real vendored ones, so a round-trip against it exercises
// the kernel-mismatch gate against genuine data, not a stand-in.
const WORKFLOW_ID = "pack-aca-226j-response-composer";

test("buildWorkflowExport: produces a schema-valid, secrets-stripped export for a real pack", () => {
  const doc = buildWorkflowExport(WORKFLOW_ID, { now: "2026-07-24T00:00:00.000Z" });
  const errs = validate(SCHEMA, doc);
  assert.deepEqual(errs, [], `export failed schema validation: ${errs.join(", ")}`);
  assert.equal(doc.result, "ok");
  assert.equal(doc.secrets_stripped, true);
  assert.ok(doc.kernel_pins.length >= 3);
  assert.match(doc.workflow_manifest_digest, /^sha256:[0-9a-f]{64}$/);
});

test("buildWorkflowExport: throws on an unknown workflow_id instead of an empty export", () => {
  assert.throws(() => buildWorkflowExport("does-not-exist"), /unknown workflow_id/);
});

test("round-trip: export -> serialize -> parse -> manifest digest identical, no mangling", () => {
  const exported = buildWorkflowExport(WORKFLOW_ID);
  const onDisk = JSON.parse(JSON.stringify(exported)); // simulates a file write+read
  const result = parseWorkflowExport(onDisk);
  assert.equal(result.ok, true);
  assert.equal(result.workflow_id, exported.workflow_id);
  assert.deepEqual(result.manifest, exported.workflow_manifest);
  assert.deepEqual(result.kernelPins, exported.kernel_pins);

  const reExported = { ...exported, workflow_manifest: result.manifest };
  assert.deepEqual(reExported, exported, "second export from the round-tripped manifest must be byte-identical");
});

test("round-trip also works from a raw JSON string (real file-on-disk shape)", () => {
  const exported = buildWorkflowExport(WORKFLOW_ID);
  const result = parseWorkflowExport(JSON.stringify(exported));
  assert.equal(result.ok, true);
  assert.equal(result.workflow_id, WORKFLOW_ID);
});

test("mismatch-refusal: unsupported format_version is refused, never partially imported", () => {
  const exported = buildWorkflowExport(WORKFLOW_ID);
  const future = { ...exported, format_version: "2" };
  const result = parseWorkflowExport(future);
  assert.equal(result.ok, false);
  assert.equal(result.result, "refused");
  assert.equal(result.format_version, "2");
  assert.equal(result.minimum_supported_version, "1");
  assert.match(result.reason, /unsupported format_version/);
});

test("mismatch-refusal: tampered workflow_manifest (digest no longer matches) is refused", () => {
  const exported = buildWorkflowExport(WORKFLOW_ID);
  const tampered = { ...exported, workflow_manifest: { ...exported.workflow_manifest, workflow_id: "swapped" } };
  const result = parseWorkflowExport(tampered);
  assert.equal(result.result, "refused");
  assert.match(result.reason, /workflow_manifest_digest/);
});

test("mismatch-refusal: kernel_digest pin mismatch is refused with the offending kernel named", () => {
  const exported = buildWorkflowExport(WORKFLOW_ID);
  const badPins = exported.kernel_pins.map((p, i) =>
    i === 0 ? { ...p, kernel_digest: "sha256:" + "0".repeat(64) } : p
  );
  const tampered = { ...exported, kernel_pins: badPins };
  const result = parseWorkflowExport(tampered);
  assert.equal(result.result, "refused");
  assert.match(result.reason, new RegExp(badPins[0].kernel_id));
  assert.match(result.reason, /version mismatch/);
});

test("mismatch-refusal: unknown vendored kernel is refused, not silently dropped", () => {
  const exported = buildWorkflowExport(WORKFLOW_ID);
  const badPins = [...exported.kernel_pins, { node_id: "nX", kernel_id: "art-does-not-exist", kernel_digest: "sha256:" + "1".repeat(64) }];
  const result = parseWorkflowExport({ ...exported, kernel_pins: badPins });
  assert.equal(result.result, "refused");
  assert.match(result.reason, /not vendored/);
});

test("mismatch-refusal: malformed JSON is refused, not thrown", () => {
  const result = parseWorkflowExport("{not json");
  assert.equal(result.result, "refused");
  assert.match(result.reason, /not valid JSON/);
});

test("secrets-grep gate: a real export never serializes a literal secret", () => {
  const doc = buildWorkflowExport(WORKFLOW_ID);
  const serialized = JSON.stringify(doc);
  assert.doesNotMatch(serialized, /sk_live_|ghp_|BEGIN (RSA |EC )?PRIVATE KEY|"password"\s*:|"api_key"\s*:\s*"[^"]/i);
  const envOverlays = doc.workflow_manifest.env_overlays ?? [];
  for (const overlay of envOverlays) {
    assert.deepEqual(Object.keys(overlay), ["vault_ref"], "env_overlays must carry vault_ref only, never a literal value");
  }
});

test("fixtures/workflow_export/golden.json is schema-valid", () => {
  const golden = JSON.parse(readFileSync(join(FIXTURES, "golden.json"), "utf8"));
  const errs = validate(SCHEMA, golden);
  assert.deepEqual(errs, [], `golden fixture failed schema validation: ${errs.join(", ")}`);
});

test("fixtures/workflow_export/tampered.json fails schema validation (injected secret field)", () => {
  const tampered = JSON.parse(readFileSync(join(FIXTURES, "tampered.json"), "utf8"));
  const errs = validate(SCHEMA, tampered);
  assert.ok(errs.length > 0, "tampered fixture should fail schema validation");
  assert.ok(
    errs.some((e) => /vault_env_secret/.test(e) || /secrets_stripped/.test(e)),
    `expected an error naming the injected secret field or secrets_stripped, got: ${errs.join(", ")}`
  );
});

test("golden.json is also refused at the import layer (its manifest digest is a stand-in, not a real hash)", () => {
  const golden = JSON.parse(readFileSync(join(FIXTURES, "golden.json"), "utf8"));
  const result = parseWorkflowExport(golden);
  assert.equal(result.result, "refused");
});
