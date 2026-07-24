// `.helm.json` workflow export/import (HELM-P3-W11, HELM-PHASE3-BUILD-SPEC.md
// §3 item 4). The email-able workflow file — n8n's spread mechanic without
// n8n's silent-mangle-on-skew failure mode. A compiled pack's manifest
// already carries no literal secrets (env_overlays are vault_ref-only,
// schema/workflow-manifest.schema.json's additionalProperties:false enforces
// it structurally) so export is a pure re-shape of what packs.mjs already
// serves; import NEVER attempts a partial/best-effort read — any version,
// shape, digest, or kernel mismatch is a refused shape with a human-readable
// reason, never a silent mangle.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { getPack } from "./packs.mjs";
import { pinnedKernelDigest } from "./kernel-runner.mjs";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = JSON.parse(readFileSync(join(HERE, "..", "schema", "workflow_export.schema.json"), "utf8"));

const FORMAT_VERSION = "1";
const MINIMUM_SUPPORTED_VERSION = "1";

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Mirrors ui/lib/manifest-digest.mjs's manifestDigest() exactly (same
// cgCanon, same SHA-256) so a browser-computed digest and this daemon-side
// one always agree — kept as separate copies per that module's own note:
// ui/ ships static with no build step, hub/vendored isn't served to it.
function workflowManifestDigest(manifest) {
  assertIJson(manifest);
  return `sha256:${sha256Hex(Buffer.from(JSON.stringify(cgCanon(manifest)), "utf8"))}`;
}

function refused(formatVersion, reason) {
  return {
    ok: false,
    format_version: formatVersion ?? "unknown",
    result: "refused",
    reason,
    minimum_supported_version: MINIMUM_SUPPORTED_VERSION,
  };
}

// Builds a versioned, secrets-stripped, kernel-hash-pinned `.helm.json`
// document for a compiled pack. Throws on an unknown workflow_id (same
// contract as euc-register.mjs's buildEucEntry) — there is no "empty export"
// shape, a caller asking to export nothing is a caller bug.
export function buildWorkflowExport(workflowId, { now } = {}) {
  const pack = getPack(workflowId);
  if (!pack) throw new Error(`workflow-export: unknown workflow_id "${workflowId}" (not a compiled pack)`);

  const manifest = pack.manifest;
  const kernelPins = (manifest.nodes ?? []).map((n) => ({
    node_id: n.node_id,
    kernel_id: n.kernel_id,
    kernel_digest: n.kernel_digest,
  }));

  const doc = {
    format_version: FORMAT_VERSION,
    result: "ok",
    workflow_id: pack.workflow_id,
    exported_at: now ?? new Date().toISOString(),
    secrets_stripped: true,
    kernel_pins: kernelPins,
    workflow_manifest_digest: workflowManifestDigest(manifest),
    workflow_manifest: manifest,
  };

  const errs = validate(SCHEMA, doc);
  if (errs.length) {
    // Unreachable in practice (this function builds the shape from schema-
    // known fields) — surfaced loudly rather than shipping a document this
    // module's own importer would refuse.
    throw new Error(`workflow-export: built export fails its own schema — ${errs.join("; ")}`);
  }
  return doc;
}

// Parses + validates a `.helm.json` file's contents. Always returns one of
// {ok:true, workflow_id, manifest, kernelPins} or a refused shape
// ({ok:false, format_version, result:"refused", reason,
// minimum_supported_version}) — never throws, never returns a partial
// import. Checks run cheapest-and-most-explanatory first: JSON parse ->
// format_version -> full schema shape -> manifest digest integrity -> each
// pinned kernel against what THIS install actually has vendored.
export function parseWorkflowExport(raw) {
  let doc;
  try {
    doc = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    return refused(undefined, "not valid JSON");
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    return refused(undefined, "not a JSON object");
  }
  if (doc.format_version !== FORMAT_VERSION) {
    return refused(
      doc.format_version,
      `unsupported format_version "${doc.format_version}" — this importer supports version ${FORMAT_VERSION} only; re-export from a Helm install on a compatible version`
    );
  }
  if (doc.result === "refused") {
    return refused(doc.format_version, doc.reason ?? "file is itself an export refusal, not an importable workflow");
  }

  const errs = validate(SCHEMA, doc);
  if (errs.length) {
    return refused(doc.format_version, `file does not match the .helm.json schema — ${errs.slice(0, 3).join("; ")}`);
  }

  let recomputedDigest;
  try {
    recomputedDigest = workflowManifestDigest(doc.workflow_manifest);
  } catch (err) {
    return refused(doc.format_version, `could not hash the embedded workflow_manifest — ${err.message}`);
  }
  if (recomputedDigest !== doc.workflow_manifest_digest) {
    return refused(
      doc.format_version,
      "workflow_manifest_digest does not match the embedded workflow_manifest — file may be corrupted or tampered"
    );
  }

  for (const pin of doc.kernel_pins) {
    let localDigest;
    try {
      localDigest = pinnedKernelDigest(pin.kernel_id);
    } catch {
      return refused(
        doc.format_version,
        `kernel "${pin.kernel_id}" is not vendored on this install — update Helm to a version that vendors it before importing`
      );
    }
    if (localDigest !== pin.kernel_digest) {
      return refused(
        doc.format_version,
        `kernel "${pin.kernel_id}" version mismatch — file pins ${pin.kernel_digest}, this install has ${localDigest}; ` +
          `update your local kernel vendoring to match, or re-export from a daemon on this version`
      );
    }
  }

  return { ok: true, workflow_id: doc.workflow_id, manifest: doc.workflow_manifest, kernelPins: doc.kernel_pins };
}
