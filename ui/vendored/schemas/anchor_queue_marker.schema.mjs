// Inlined copy of schema/anchor_queue_marker.schema.json (HELM-P3-A5) — ui/
// ships static with no build step and can't reliably fetch outside its own
// tree (file://), so ui/lib/anchor-browser.mjs shape-checks queue markers
// against this JS object, same discipline as the other
// ui/vendored/schemas/*.schema.mjs files. DO NOT hand-edit — resync from the
// schema/ copy if it changes.
export default {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ainumbers.co/helm/schema/anchor_queue_marker.schema.json",
  "title": "Browser mode — anchor queue marker (HELM-PHASE3-BUILD-SPEC.md P3-D4)",
  "description": "Recorded in place of an anchor proof when the shipped anchor relay (anchor.ainumbers.co) is unreachable at checkpoint time. Explicit, never silent: a run with all egress blocked (including the relay) MUST still produce a valid checkpoint with this marker instead of an anchors[] entry, and the offline verifier must render it as 'anchoring queued/skipped', not as an error. status=queued means a retry is still possible client-side before export; status=skipped means the checkpoint was exported without ever anchoring (zero-egress copy, P3-D4).",
  "$defs": {
    "sha256ref": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
    "timestamp": { "type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z$" }
  },
  "type": "object",
  "additionalProperties": false,
  "required": ["checkpoint_seq", "status", "reason", "relay_url", "recorded_at"],
  "properties": {
    "checkpoint_seq": { "type": "integer", "minimum": 0 },
    "status": { "type": "string", "enum": ["queued", "skipped"] },
    "reason": { "type": "string", "enum": ["relay_unreachable", "egress_blocked", "relay_error"] },
    "relay_url": { "type": "string", "minLength": 1 },
    "recorded_at": { "$ref": "#/$defs/timestamp" },
    "attempts": { "type": "integer", "minimum": 0 },
    "last_attempt_at": { "$ref": "#/$defs/timestamp" },
    "journal_root_digest": { "$ref": "#/$defs/sha256ref" }
  }
};
