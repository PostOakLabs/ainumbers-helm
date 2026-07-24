import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-pq-export-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys } = await import("./keys.mjs");
const { assembleBundle } = await import("./bundle.mjs");
const { buildPqExportFiles, writePqExportFolder } = await import("./pq-export.mjs");
const { validate } = await import("../scripts/lib/schema-validator.mjs");

const RESULTS_SCHEMA = JSON.parse(readFileSync(join(import.meta.dirname, "..", "schema", "pq_export_results.schema.json"), "utf8"));
const TRUST_LABELS_SCHEMA = JSON.parse(readFileSync(join(import.meta.dirname, "..", "schema", "pq_export_trust_labels.schema.json"), "utf8"));
const HASHES_SCHEMA = JSON.parse(readFileSync(join(import.meta.dirname, "..", "schema", "pq_export_hashes.schema.json"), "utf8"));

const keys = loadOrCreateKeys();
const RUN_ID = "run-pq-1";
const WF_DIGEST = "sha256:" + "c".repeat(64);

function fixtureBundle() {
  return assembleBundle({
    bundleId: "bundle-pq-1",
    runId: RUN_ID,
    workflowManifestDigest: WF_DIGEST,
    specs: [
      {
        kind: "connector_attestation",
        subject: [{ name: "payload", digest: { sha256: "d".repeat(64) } }],
        predicate: { run_id: RUN_ID, workflow_manifest_digest: WF_DIGEST, connector_id: "google-drive.fetch", payload_digest: "sha256:" + "d".repeat(64) },
      },
      {
        kind: "step_result",
        subject: [{ name: "execution_hash", digest: { sha256: "e".repeat(64) } }],
        predicate: { run_id: RUN_ID, step_id: "nodes:n1", output_digest: "sha256:" + "e".repeat(64) },
      },
    ],
    keys,
  });
}

test("buildPqExportFiles: produces three schema-valid files, one row per bundle entry", () => {
  const bundle = fixtureBundle();
  const { files } = buildPqExportFiles(bundle, { generatedAt: "2026-07-24T00:00:00.000Z" });
  const byName = Object.fromEntries(files.map((f) => [f.name, JSON.parse(f.data)]));

  assert.deepEqual(Object.keys(byName).sort(), ["hashes.json", "results.json", "trust-labels.json"]);
  assert.equal(validate(RESULTS_SCHEMA, byName["results.json"]).length, 0);
  assert.equal(validate(TRUST_LABELS_SCHEMA, byName["trust-labels.json"]).length, 0);
  assert.equal(validate(HASHES_SCHEMA, byName["hashes.json"]).length, 0);

  assert.equal(byName["results.json"].rows.length, 2);
  assert.equal(byName["trust-labels.json"].rows.length, 2);
  assert.equal(byName["hashes.json"].rows.length, 2);
});

test("buildPqExportFiles: results/trust-labels/hashes join cleanly on digest", () => {
  const bundle = fixtureBundle();
  const { files } = buildPqExportFiles(bundle);
  const byName = Object.fromEntries(files.map((f) => [f.name, JSON.parse(f.data)]));

  const resultDigests = new Set(byName["results.json"].rows.map((r) => r.digest));
  const labelDigests = new Set(byName["trust-labels.json"].rows.map((r) => r.digest));
  const hashDigests = new Set(byName["hashes.json"].rows.map((r) => r.digest));
  assert.deepEqual(resultDigests, labelDigests);
  assert.deepEqual(resultDigests, hashDigests);

  for (const row of byName["hashes.json"].rows) {
    assert.equal(row.digest, `sha256:${row.hex}`);
  }
});

test("writePqExportFolder: writes the three files to disk at the given directory", () => {
  const bundle = fixtureBundle();
  const dir = join(TMP, "run-folder-1");
  const paths = writePqExportFolder(dir, bundle, { generatedAt: "2026-07-24T00:00:00.000Z" });

  assert.equal(paths.length, 3);
  for (const p of paths) assert.ok(existsSync(p), `expected ${p} to exist`);

  const results = JSON.parse(readFileSync(join(dir, "results.json"), "utf8"));
  assert.equal(results.run_id, RUN_ID);
  assert.equal(results.bundle_id, "bundle-pq-1");
  assert.equal(results.schema_version, 1);
});
