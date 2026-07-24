// Browser connector runtime (HELM-P3-U4). Reuses the SAME contract shape as
// hub/connector.mjs — schema/connector_contract.schema.json, vendored here
// as ui/vendored/schemas/connector_contract.schema.mjs — and the SAME
// default-deny (host, method) allowlist semantics: a connector may only
// reach a (host, method) pair present in its OWN contract's allowlist, no
// wildcards, no path matching. Only the transport (browser fetch vs Node
// fetch+dns) and the credential source (VaultTokenStore vs hub/vault.mjs)
// differ. Keep assertEgressAllowed in sync with hub/connector.mjs's copy if
// either changes.
//
// Two platform gaps vs. the daemon runtime, both structural, not oversights:
//   1. DNS-rebinding pin (HELM-P2-H9a): a browser JS context has no raw
//      DNS/socket API to resolve-then-pin against. There is no browser
//      equivalent to attempt — the browser's own Same-Origin/CORS model is
//      the platform's substitute network boundary for this transport.
//   2. Redirect re-vetting: hub/connector.mjs re-checks every redirect hop
//      against the contract because Node's fetch (redirect:"manual") still
//      exposes the 3xx status and Location header. A BROWSER fetch in
//      redirect:"manual" mode instead returns an opaque, unreadable
//      response (type "opaqueredirect", status 0, no headers) for any
//      cross-origin redirect — by design, per the Fetch spec's CORS
//      protections. This runtime treats an opaque redirect as a blocked
//      egress (fail closed) rather than pretending it can inspect and
//      re-vet the target; connectors used from the browser should target
//      APIs that don't redirect across hosts.
import { validate } from "../vendored/schema-validator.mjs";
import CONNECTOR_CONTRACT_SCHEMA from "../vendored/schemas/connector_contract.schema.mjs";
import { cgCanon, assertIJson } from "../vendored/hash.mjs";

async function sha256Hex(bytes, cryptoImpl = crypto) {
  const digest = await cryptoImpl.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function jcsDigestHex(obj, cryptoImpl) {
  assertIJson(obj);
  return sha256Hex(new TextEncoder().encode(JSON.stringify(cgCanon(obj))), cryptoImpl);
}

function sha256ref(hex) {
  return `sha256:${hex}`;
}

// Validates an already-parsed contract object — the browser has no
// filesystem, so unlike hub/connector.mjs's loadContract(path), the caller
// fetches/imports the contract JSON itself and hands the parsed object here.
export async function loadContractFromObject(raw, { cryptoImpl = crypto } = {}) {
  const errs = validate(CONNECTOR_CONTRACT_SCHEMA, raw);
  if (errs.length) throw new Error(`connector contract invalid: ${errs.join("; ")}`);
  const digest = await jcsDigestHex(raw, cryptoImpl);
  return { contract: raw, contractDigest: sha256ref(digest) };
}

// Identical semantics to hub/connector.mjs's assertEgressAllowed.
export function assertEgressAllowed(contract, { host, method }) {
  return contract.allowed_hosts.includes(host) && contract.allowed_methods.includes(method);
}

const MAX_REDIRECTS = 5;

// The browser runtime's single egress choke point, mirroring
// hub/connector.mjs's performEgress: the contract is re-checked before every
// hop, a blocked call throws (never returns a fake response) AND is reported
// through `onEgress` before the throw so the transcript records the block,
// and the credential is resolved from the vault at this boundary — send()
// implementations never see the raw token. `tokenStore` is a
// VaultTokenStore-shaped object ({getToken(ref)}); `onEgress` receives the
// same decision-record shape hub/connector.mjs journals (connectorId,
// destinationHost, operation, decision, requestDigest, responseDigest), so
// callers can pipe it into window.helmJournal.append (P3-U2) without this
// module knowing anything about OPFS.
export async function performEgress({
  contract,
  connectorId,
  url,
  method,
  headers = {},
  body = null,
  credential = null,
  tokenStore = null,
  fetchImpl = fetch,
  cryptoImpl = crypto,
  onEgress = () => {},
}) {
  let resolvedHeaders = headers;
  if (credential) {
    if (!tokenStore) throw new Error("connector-browser: credential requested but no tokenStore given");
    const secret = await tokenStore.getToken(credential.ref);
    if (!secret) throw new Error(`connector-browser: no token stored at ref ${credential.ref}`);
    const value = secret.access_token ?? secret.token ?? secret;
    if (!value) throw new Error(`connector-browser: ref ${credential.ref} carried no usable bearer value`);
    resolvedHeaders = { ...headers, Authorization: `Bearer ${value}` };
  }

  let currentUrl = url;
  let hops = 0;

  for (;;) {
    const host = new URL(currentUrl).host;
    const requestDigest = sha256ref(
      await jcsDigestHex({ url: currentUrl, method, headerNames: Object.keys(resolvedHeaders).sort() }, cryptoImpl)
    );

    if (!assertEgressAllowed(contract, { host, method })) {
      onEgress({ connectorId, destinationHost: host, operation: method, decision: "blocked", requestDigest });
      throw new Error(`egress blocked: ${connectorId} -> ${method} ${host} not in contract allowlist`);
    }

    const res = await fetchImpl(currentUrl, { method, headers: resolvedHeaders, body, redirect: "manual" });

    // Opaque cross-origin redirect (real browsers) — can't inspect the
    // target to re-vet it, so fail closed rather than blindly follow it.
    if (res.type === "opaqueredirect") {
      onEgress({ connectorId, destinationHost: host, operation: method, decision: "blocked", requestDigest });
      throw new Error(`egress blocked: ${connectorId} -> opaque redirect from ${host} cannot be re-vetted in a browser`);
    }

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      onEgress({ connectorId, destinationHost: host, operation: method, decision: "allowed", requestDigest });
      if (++hops > MAX_REDIRECTS) {
        throw new Error(`egress blocked: ${connectorId} -> too many redirects (>${MAX_REDIRECTS}) from ${host}`);
      }
      currentUrl = new URL(res.headers.get("location"), currentUrl).toString();
      continue;
    }

    const bodyBytes = new Uint8Array(await res.arrayBuffer());
    const responseDigest = sha256ref(await sha256Hex(bodyBytes, cryptoImpl));
    onEgress({ connectorId, destinationHost: host, operation: method, decision: "allowed", requestDigest, responseDigest });
    return { status: res.status, headers: res.headers, body: bodyBytes };
  }
}
