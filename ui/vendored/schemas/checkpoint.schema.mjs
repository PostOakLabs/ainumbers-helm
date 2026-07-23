// Inlined copy of schema/checkpoint.schema.json (HELM-U3) — ui/ ships static with
// no build step and can't fetch outside its own tree reliably (file://), so the
// two schemas the Verify view shape-checks travel as JS objects, same
// discipline as ui/vendored/*.mjs. DO NOT hand-edit — resync from the schema/
// copy if it changes.
export default {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ainumbers.co/helm/schema/checkpoint.schema.json",
  "title": "Control Plane Profile \u00e2\u20ac\u201d checkpoint (SPEC.md \u00c2\u00a726.5)",
  "description": "Signed (\u00c2\u00a726.2) summary emitted periodically and at run completion. This schema validates the checkpoint PREDICATE shape (the object carried inside an envelope's statement.predicate, predicateType #checkpoint). anchors[].type is intentionally an open string, not an enum \u00e2\u20ac\u201d \u00c2\u00a726.5 requires unknown anchor types be reported as unrecognized, never rejected as invalid shape. scitt-receipt is reserved: producers MUST NOT emit it under @1 (a policy rule enforced by validate-checkpoint-anchors.test.mjs in HELM-H3, not by this shape schema).",
  "$defs": {
    "sha256ref": {
      "type": "string",
      "pattern": "^sha256:[0-9a-f]{64}$"
    },
    "rawSha256Hex": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$"
    },
    "streamCheckpoint": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "stream_id",
        "journal_seq",
        "rh"
      ],
      "properties": {
        "stream_id": {
          "type": "string",
          "minLength": 1
        },
        "journal_seq": {
          "type": "integer",
          "minimum": 0
        },
        "rh": {
          "$ref": "#/$defs/rawSha256Hex"
        }
      }
    },
    "anchor": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string",
          "pattern": "^[a-z][a-z0-9-]*$"
        },
        "proof": {
          "type": "string",
          "minLength": 1
        },
        "log_origin": {
          "type": "string",
          "minLength": 1
        }
      }
    }
  },
  "type": "object",
  "additionalProperties": false,
  "required": [
    "checkpoint_seq",
    "streams",
    "journal_root_digest",
    "anchors"
  ],
  "properties": {
    "checkpoint_seq": {
      "type": "integer",
      "minimum": 0
    },
    "streams": {
      "type": "array",
      "minItems": 1,
      "items": {
        "$ref": "#/$defs/streamCheckpoint"
      }
    },
    "journal_root_digest": {
      "$ref": "#/$defs/sha256ref"
    },
    "anchors": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/anchor"
      }
    }
  }
};
