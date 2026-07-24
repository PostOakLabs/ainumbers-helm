// Inlined copy of schema/connector_contract.schema.json (HELM-P3-U4) — ui/
// ships static with no build step and can't reliably fetch outside its own
// tree (file://), so the browser connector runtime (ui/lib/connector-browser.mjs)
// shape-checks contracts against this JS object, same discipline as the
// other ui/vendored/schemas/*.schema.mjs files. DO NOT hand-edit — resync
// from the schema/ copy if it changes.
export default {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ainumbers.co/helm/schema/connector_contract.schema.json",
  "title": "Control Plane Profile — connector contract (HELM-H6 D-class)",
  "description": "Signed contract loaded by the connector runtime: default-deny egress allowlist + the scoped vault slice a connector may read. contract_digest (referenced by workflow manifests and connector_attestation objects) is the SHA-256 of THIS document's JCS-canonical form and is not stored inside it.",
  "type": "object",
  "additionalProperties": false,
  "required": ["connector_id", "connector_version", "publisher", "allowed_hosts", "allowed_methods", "scopes"],
  "properties": {
    "connector_id": { "type": "string", "minLength": 1 },
    "connector_version": { "type": "string", "minLength": 1 },
    "publisher": { "type": "string", "minLength": 1 },
    "allowed_hosts": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
    "allowed_methods": { "type": "array", "minItems": 1, "items": { "type": "string", "minLength": 1 } },
    "scopes": { "type": "array", "items": { "type": "string", "minLength": 1 } },
    "vault_scope": { "type": "array", "items": { "type": "string", "minLength": 1 }, "description": "Opaque vault refs this connector may read. NEVER secret values." }
  }
};
