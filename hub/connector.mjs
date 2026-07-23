// Connector runtime (D-class, HELM-H6). Loads signed connector contracts
// (schema/connector_contract.schema.json) and enforces DEFAULT-DENY egress:
// a connector may only reach a (host, method) pair present in its OWN
// contract's allowlist — no wildcard, no fallthrough. Every egress decision
// (allowed or blocked) is journaled to an append-only per-connector stream so
// a block is provable evidence, not a silently swallowed error (§4 negative
// test: "unapproved host blocked + transcript records the block").
//
// Lifecycle borrowed from archive/BROWSERCHAIN-LANDING-BUILD-SPEC.md §4:
// init(vaultSlice, config) -> selfTest() -> send(payload) -> dispose().
// Connector code only ever sees its own scoped vault slice (contract's
// vault_scope refs), never the whole vault.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { lookup as dnsLookup } from "node:dns/promises";
import { isIP } from "node:net";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { appendEntry } from "./journal.mjs";
import { attachCredential } from "./credential-provider.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACT_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "schema", "connector_contract.schema.json"), "utf8")
);

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

function sha256ref(hex) {
  return `sha256:${hex}`;
}

// contract_digest is the SHA-256 of the contract's OWN JCS-canonical form
// (schema description) — never stored inside the contract document itself.
export function loadContract(contractPath) {
  const raw = JSON.parse(readFileSync(contractPath, "utf8"));
  const errs = validate(CONTRACT_SCHEMA, raw);
  if (errs.length) {
    throw new Error(`connector contract invalid (${contractPath}): ${errs.join("; ")}`);
  }
  return { contract: raw, contractDigest: sha256ref(jcsDigestHex(raw)) };
}

// Host+method match against the contract's own allowlist. No path matching,
// no wildcards: a connector contract enumerates exactly what it may reach.
export function assertEgressAllowed(contract, { host, method }) {
  return contract.allowed_hosts.includes(host) && contract.allowed_methods.includes(method);
}

// --- DNS-rebinding hardening (HELM-P2-H9a) ---------------------------------
// A hostname-only allowlist is defeated by DNS rebinding: an allowlisted
// name can resolve to a private/link-local/metadata IP the operator never
// meant to expose. Every hop in performEgress additionally resolves the
// hostname and checks the RESULTING IP against a hardcoded deny list, on
// top of (never instead of) the contract's own hostname allowlist.
//
// Scope (Fable review 07-23, LOCKED): this deny list applies ONLY to
// outbound connector calls routed through performEgress below. The
// daemon's own loopback API (server.mjs) and the RFC 8252 OAuth loopback
// redirect (oauth-pkce.mjs) both call fetch/http directly and never pass
// through here — so their legitimate 127.0.0.1 use is unaffected by
// construction, not by a carve-out in this list. Do not import this list
// elsewhere and do not loosen it for those callers.
const DENIED_V4_RANGES = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT — also commonly used for cloud-internal routing
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, includes the 169.254.169.254 cloud metadata address
  ["172.16.0.0", 12],
  ["192.168.0.0", 16],
];

function ipv4ToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

function isDeniedV4(ip) {
  const target = ipv4ToInt(ip);
  return DENIED_V4_RANGES.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (target & mask) === (ipv4ToInt(base) & mask);
  });
}

// Expands any legal IPv6 literal (including "::" compression and a trailing
// embedded IPv4 tail like "::ffff:127.0.0.1") to 8 hex groups.
function expandIPv6(ip) {
  const noZone = ip.split("%")[0];
  const [headStr, tailStr] = noZone.includes("::") ? noZone.split("::") : [noZone, null];
  const headParts = headStr ? headStr.split(":").filter(Boolean) : [];
  const tailParts = tailStr ? tailStr.split(":").filter(Boolean) : [];
  for (const parts of [headParts, tailParts]) {
    if (parts.length && parts[parts.length - 1].includes(".")) {
      const v4 = parts.pop().split(".").map(Number);
      parts.push((((v4[0] << 8) + v4[1]) >>> 0).toString(16));
      parts.push((((v4[2] << 8) + v4[3]) >>> 0).toString(16));
    }
  }
  const missing = Math.max(0, 8 - headParts.length - tailParts.length);
  const groups = [...headParts, ...new Array(missing).fill("0"), ...tailParts];
  while (groups.length < 8) groups.push("0");
  return groups.slice(0, 8).map((g) => g.padStart(4, "0"));
}

function ipv6ToBigInt(ip) {
  return expandIPv6(ip).reduce((acc, g) => (acc << 16n) + BigInt(parseInt(g, 16)), 0n);
}

const DENIED_V6_RANGES = [
  ["::1", 128], // loopback
  ["::", 128], // unspecified
  ["fe80::", 10], // link-local
  ["fc00::", 7], // unique local (ULA)
];

function isDeniedV6(ip) {
  const target = ipv6ToBigInt(ip);
  return DENIED_V6_RANGES.some(([base, bits]) => {
    const mask = bits === 0 ? 0n : (((1n << 128n) - 1n) << BigInt(128 - bits)) & ((1n << 128n) - 1n);
    return (target & mask) === (ipv6ToBigInt(base) & mask);
  });
}

function isDeniedIp(ip) {
  const kind = isIP(ip);
  if (kind === 4) return isDeniedV4(ip);
  if (kind === 6) {
    const mapped = ip.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isDeniedV4(mapped[1]);
    return isDeniedV6(ip);
  }
  return true; // not a recognizable literal — refuse rather than guess
}

// Overridable only for tests (real DNS is not reachable/deterministic in
// the sandboxed test runner). Production always uses node:dns/promises.
let resolveHostIps = async (hostname) => (await dnsLookup(hostname, { all: true })).map((a) => a.address);
export function __setHostResolverForTest(fn) {
  resolveHostIps = fn ?? (async (hostname) => (await dnsLookup(hostname, { all: true })).map((a) => a.address));
}

// Throws if `hostname` is itself a denied IP literal, or resolves to one.
export async function assertResolvedIpAllowed(hostname) {
  if (isIP(hostname)) {
    if (isDeniedIp(hostname)) {
      throw new Error(`egress blocked: ${hostname} is a private/link-local/metadata address`);
    }
    return;
  }
  const addresses = await resolveHostIps(hostname);
  for (const ip of addresses) {
    if (isDeniedIp(ip)) {
      throw new Error(`egress blocked: ${hostname} resolves to ${ip}, a private/link-local/metadata address (DNS rebinding guard)`);
    }
  }
}

// Exported so inbound-direction connectors (no outbound fetch of their own,
// e.g. the webhook adapter) can journal a boundary-crossing decision through
// the same transcript shape rather than inventing a second journal kind.
export function recordEgress(db, { connectorId, destinationHost, operation, decision, requestDigest, responseDigest = null }) {
  const now = new Date().toISOString();
  return appendEntry(db, {
    streamId: `egress:${connectorId}`,
    kind: "egress",
    entry: {
      period_start: now,
      period_end: now,
      reference_db_version: "helm-connector-runtime@1",
      triggering_input_digest: requestDigest,
      humans_involved: [],
      connector_id: connectorId,
      destination_host: destinationHost,
      operation,
      decision,
      request_digest: requestDigest,
      response_digest: responseDigest,
    },
  });
}

const MAX_REDIRECTS = 5;
const EGRESS_TIMEOUT_MS = 15 * 1000; // HELM-SEC-5 hardening: a hung connector endpoint must not stall the runtime forever

// The single egress choke point every connector implementation MUST route
// through — a blocked call throws (never returns a fake response) AND is
// journaled before the throw, so the transcript records the block even
// though the caller sees only an exception.
//
// redirect:"manual" so every hop (including redirect targets) gets its own
// allowlist check + journal entry — Node's default redirect:"follow" would
// silently egress to a redirect target never checked against the contract
// (HELM-R1 finding F1: allowlisted host -> 3xx -> blocked host bypassed §5
// gate #3, transcript recorded only the original host).
// `credential`, if given, is an opaque { ref, scheme, ... } descriptor —
// see credential-provider.mjs. Resolved to an actual header value HERE, at
// the egress boundary, so the caller (connector send() code) never handles
// the raw secret at all.
export async function performEgress(db, { contract, connectorId, url, method, headers = {}, body = null, credential = null }) {
  const resolvedHeaders = credential ? attachCredential(headers, credential) : headers;
  let currentUrl = url;
  let hops = 0;

  for (;;) {
    const host = new URL(currentUrl).host;
    const hostname = new URL(currentUrl).hostname;
    const requestDigest = sha256ref(jcsDigestHex({ url: currentUrl, method, headerNames: Object.keys(resolvedHeaders).sort() }));

    if (!assertEgressAllowed(contract, { host, method })) {
      recordEgress(db, { connectorId, destinationHost: host, operation: method, decision: "blocked", requestDigest });
      throw new Error(`egress blocked: ${connectorId} -> ${method} ${host} not in contract allowlist`);
    }

    try {
      await assertResolvedIpAllowed(hostname);
    } catch (err) {
      recordEgress(db, { connectorId, destinationHost: host, operation: method, decision: "blocked", requestDigest });
      throw err;
    }

    const res = await fetch(currentUrl, {
      method,
      headers: resolvedHeaders,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(EGRESS_TIMEOUT_MS),
    });

    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      recordEgress(db, { connectorId, destinationHost: host, operation: method, decision: "allowed", requestDigest });
      if (++hops > MAX_REDIRECTS) {
        throw new Error(`egress blocked: ${connectorId} -> too many redirects (>${MAX_REDIRECTS}) from ${host}`);
      }
      currentUrl = new URL(res.headers.get("location"), currentUrl).toString();
      continue;
    }

    const bodyBytes = Buffer.from(await res.arrayBuffer());
    const responseDigest = sha256ref(createHash("sha256").update(bodyBytes).digest("hex"));
    recordEgress(db, { connectorId, destinationHost: host, operation: method, decision: "allowed", requestDigest, responseDigest });

    return { status: res.status, headers: res.headers, body: bodyBytes };
  }
}

// Builds a connector_attestation object (SPEC.md §26.4): trust label
// connector_asserted — no claim about payload truth, only that an authorized
// connector retrieved/received it. payload_digest binds the actual bytes
// without exporting them.
export function buildConnectorAttestation({
  runId, workflowManifestDigest, connectorId, connectorVersion, contractDigest,
  operation, scope, endpointHost, payloadBytes, classification = "unclassified",
}) {
  return {
    run_id: runId,
    workflow_manifest_digest: workflowManifestDigest,
    recorded_at: new Date().toISOString(),
    connector_id: connectorId,
    connector_version: connectorVersion,
    contract_digest: contractDigest,
    operation,
    scope,
    endpoint_host: endpointHost,
    payload_digest: sha256ref(createHash("sha256").update(payloadBytes).digest("hex")),
    classification,
  };
}
