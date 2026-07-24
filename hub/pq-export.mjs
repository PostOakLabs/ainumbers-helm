// Power Query bridge (HELM-P4-B1, HELM-PHASE4-BUILD-SPEC.md §2 Band B row B1):
// writes a run's evidence-bundle entries out as a small, FROZEN-schema JSON
// output-folder that Excel/Power Query reads natively, offline, in
// local-file mode (banks GPO-block unapproved web connections — see
// docs/POWER-QUERY-BRIDGE.md). Three files, joined on `digest`:
//   results.json       — kind + run/bundle linkage per entry
//   trust-labels.json  — §26.6 trust label per entry
//   hashes.json        — digest split into algorithm + hex columns
// Schema is versioned via the `schema_version` field in each file
// (schema/pq_export_*.schema.json) — a shape change is a major-version bump,
// never an in-place edit (see docs/POWER-QUERY-BRIDGE.md).
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA_DIR = join(HERE, "..", "schema");

function loadSchema(name) {
  return JSON.parse(readFileSync(join(SCHEMA_DIR, name), "utf8"));
}

const RESULTS_SCHEMA = loadSchema("pq_export_results.schema.json");
const TRUST_LABELS_SCHEMA = loadSchema("pq_export_trust_labels.schema.json");
const HASHES_SCHEMA = loadSchema("pq_export_hashes.schema.json");

function hexOf(digest) {
  return digest.replace(/^sha256:/, "");
}

// bundle: an assembleBundle()/exportBundleZip() result — { manifest: { predicate }, ... }.
// Returns { files: [{ name, data }] } — `data` is pretty-printed JSON text,
// schema-validated before returning (throws on a shape bug rather than
// writing a file Power Query would silently choke on).
export function buildPqExportFiles(bundle, { generatedAt } = {}) {
  const predicate = bundle.manifest.predicate;
  const header = {
    generated_at: generatedAt ?? new Date(0).toISOString(),
    run_id: predicate.run_id,
    bundle_id: predicate.bundle_id,
  };

  const results = {
    schema_version: 1,
    ...header,
    workflow_manifest_digest: predicate.workflow_manifest_digest,
    rows: predicate.entries.map((e) => ({
      digest: e.digest,
      kind: e.kind,
      run_id: predicate.run_id,
      bundle_id: predicate.bundle_id,
    })),
  };
  const trustLabels = {
    schema_version: 1,
    ...header,
    rows: predicate.entries.map((e) => ({ digest: e.digest, trust_label: e.trust_label })),
  };
  const hashes = {
    schema_version: 1,
    ...header,
    rows: predicate.entries.map((e) => ({ digest: e.digest, algorithm: "sha256", hex: hexOf(e.digest) })),
  };

  for (const [payload, schema, name] of [
    [results, RESULTS_SCHEMA, "results.json"],
    [trustLabels, TRUST_LABELS_SCHEMA, "trust-labels.json"],
    [hashes, HASHES_SCHEMA, "hashes.json"],
  ]) {
    const errs = validate(schema, payload);
    if (errs.length) throw new Error(`pq-export: ${name} fails schema — ${errs.join("; ")}`);
  }

  return {
    files: [
      { name: "results.json", data: JSON.stringify(results, null, 2) },
      { name: "trust-labels.json", data: JSON.stringify(trustLabels, null, 2) },
      { name: "hashes.json", data: JSON.stringify(hashes, null, 2) },
    ],
  };
}

// LOCAL-FILE mode primary (HELM-PHASE4-BUILD-SPEC.md §2 B1): writes the
// output-folder to a real path on disk so Excel's Power Query "From Folder"
// / "From JSON" connectors can point at it directly — no daemon-API call
// required. Returns the absolute paths written.
export function writePqExportFolder(dir, bundle, { generatedAt } = {}) {
  mkdirSync(dir, { recursive: true });
  const { files } = buildPqExportFiles(bundle, { generatedAt });
  return files.map((f) => {
    const path = join(dir, f.name);
    writeFileSync(path, f.data, "utf8");
    return path;
  });
}
