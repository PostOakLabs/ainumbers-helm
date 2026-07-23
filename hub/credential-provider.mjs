// Credential provider (HELM-P2-H9a). The ONLY place a connector-egress call
// resolves an opaque vault_scope ref to an actual secret value. Callers
// (connector.mjs's performEgress) pass a { ref, scheme } descriptor; this
// module does the vaultGet and returns headers already carrying the
// resolved credential — connector send() implementations never touch the
// plaintext secret themselves. Built AROUND the shipped, R1/SEC-reviewed
// hub/vault.mjs (§6) — no new storage tier, no re-platform.
import { vaultGet } from "./vault.mjs";

// scheme: "bearer" (default) | "basic" | "api-key-header"
// ref:    opaque vault ref (contract's vault_scope entry)
// field:  optional key to pull off the stored secret object; defaults to
//         access_token/token for bearer, password for basic, the whole
//         value for api-key-header.
// header: header name for api-key-header (default "X-Api-Key").
export function attachCredential(headers, { ref, scheme = "bearer", field, header = "X-Api-Key" } = {}) {
  if (!ref) throw new Error("credential-provider: credential requires a vault ref");
  const secret = vaultGet(ref);
  if (secret === null || secret === undefined) {
    throw new Error(`credential-provider: no secret stored at ref ${ref}`);
  }

  switch (scheme) {
    case "bearer": {
      const value = field ? secret[field] : (secret.access_token ?? secret.token ?? secret);
      if (!value) throw new Error(`credential-provider: ref ${ref} carried no usable bearer value`);
      return { ...headers, Authorization: `Bearer ${value}` };
    }
    case "basic": {
      const user = secret.username ?? "";
      const pass = field ? secret[field] : (secret.password ?? secret);
      if (!pass) throw new Error(`credential-provider: ref ${ref} carried no usable basic-auth value`);
      return { ...headers, Authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}` };
    }
    case "api-key-header": {
      const value = field ? secret[field] : (secret.api_key ?? secret);
      if (!value) throw new Error(`credential-provider: ref ${ref} carried no usable api-key value`);
      return { ...headers, [header]: value };
    }
    default:
      throw new Error(`credential-provider: unknown scheme "${scheme}"`);
  }
}

// Presence-only check — lets connector selfTest()s report readiness without
// ever pulling the secret value into their own scope.
export function credentialExists(ref) {
  if (!ref) return false;
  const secret = vaultGet(ref);
  return secret !== null && secret !== undefined;
}
