// Inlined copy of schema/company_profile.schema.json (HELM-P4-J1) — ui/ ships
// static with no build step and can't fetch outside its own tree reliably
// (file://), so this schema travels as a JS object, same discipline as the
// other ui/vendored/schemas/*.mjs copies. DO NOT hand-edit — resync from the
// schema/ copy if it changes.
export default {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://ainumbers.co/helm/schema/company_profile.schema.json",
  "title": "Helm company-profile config (HELM-P4-J1)",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "profile_name"],
  "properties": {
    "schema_version": { "const": 1 },
    "profile_name": { "type": "string", "minLength": 1, "maxLength": 200 },
    "templates": {
      "type": "array",
      "items": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*$" }
    },
    "branding": { "type": "object" },
    "relay_url": { "type": "string", "pattern": "^https://" },
    "pinned_kernel_versions": { "type": "object" }
  }
};
