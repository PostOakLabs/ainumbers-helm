// Inlined copy of schema/evidence_bundle_manifest.schema.json (HELM-U3) — ui/ ships static with
// no build step and can't fetch outside its own tree reliably (file://), so the
// two schemas the Verify view shape-checks travel as JS objects, same
// discipline as ui/vendored/*.mjs. DO NOT hand-edit — resync from the schema/
// copy if it changes.
export default {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ainumbers.co/helm/schema/evidence_bundle_manifest.schema.json",
  "title": "Control Plane Profile \u00e2\u20ac\u201d evidence bundle manifest (SPEC.md \u00c2\u00a726.7)",
  "description": "Lists every object in a self-contained, offline-verifiable evidence bundle by digest and trust label, plus the checkpoints covering their journal entries and any anchor proofs. Default exports apply the redaction_profile: no secret values, no raw credential material, no unredacted payload above the export's disclosure level (enforced at export time, not by this shape check).",
  "$defs": {
    "sha256ref": {
      "type": "string",
      "pattern": "^sha256:[0-9a-f]{64}$"
    },
    "trustLabel": {
      "type": "string",
      "enum": [
        "hash_verified",
        "kernel_verified",
        "connector_asserted",
        "human_attested",
        "external_ack_captured"
      ]
    },
    "bundleEntry": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "kind",
        "digest",
        "trust_label"
      ],
      "properties": {
        "kind": {
          "type": "string",
          "minLength": 1
        },
        "digest": {
          "$ref": "#/$defs/sha256ref"
        },
        "trust_label": {
          "$ref": "#/$defs/trustLabel"
        }
      }
    }
  },
  "type": "object",
  "additionalProperties": false,
  "required": [
    "bundle_id",
    "run_id",
    "workflow_manifest_digest",
    "entries",
    "checkpoints_ref",
    "redaction_profile"
  ],
  "properties": {
    "bundle_id": {
      "type": "string",
      "minLength": 1
    },
    "run_id": {
      "type": "string",
      "minLength": 1
    },
    "workflow_manifest_digest": {
      "$ref": "#/$defs/sha256ref"
    },
    "entries": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "#/$defs/bundleEntry"
      }
    },
    "checkpoints_ref": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/sha256ref"
      }
    },
    "anchors_ref": {
      "type": "array",
      "items": {
        "type": "string",
        "minLength": 1
      }
    },
    "redaction_profile": {
      "type": "string",
      "minLength": 1
    }
  }
};
