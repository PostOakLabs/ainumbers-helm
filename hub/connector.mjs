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
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { appendEntry } from "./journal.mjs";

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
export async function performEgress(db, { contract, connectorId, url, method, headers = {}, body = null }) {
  let currentUrl = url;
  let hops = 0;

  for (;;) {
    const host = new URL(currentUrl).host;
    const requestDigest = sha256ref(jcsDigestHex({ url: currentUrl, method, headerNames: Object.keys(headers).sort() }));

    if (!assertEgressAllowed(contract, { host, method })) {
      recordEgress(db, { connectorId, destinationHost: host, operation: method, decision: "blocked", requestDigest });
      throw new Error(`egress blocked: ${connectorId} -> ${method} ${host} not in contract allowlist`);
    }

    const res = await fetch(currentUrl, { method, headers, body, redirect: "manual" });

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
