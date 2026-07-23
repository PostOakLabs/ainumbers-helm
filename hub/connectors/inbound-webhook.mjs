// Connector 2 (HELM-H6): generic inbound webhook — the n8n/Zapier "governed
// step" adapter. The orchestrator the buyer already runs POSTs a step-
// completion callback in; this connector never calls out (no outbound
// writes in Phase 1, per spec) — it only accepts, allowlist-checks, and
// attests. Reuses the boundary-crossing transcript (connector.mjs
// recordEgress) for the inbound direction instead of a second journal kind.
import { createHash } from "node:crypto";
import { assertEgressAllowed, recordEgress, buildConnectorAttestation } from "../connector.mjs";

export const CONNECTOR_ID = "inbound-webhook";
export const CONNECTOR_VERSION = "1.0.0";

export function createInboundWebhookConnector({ db, contract, contractDigest }) {
  let vaultSlice = null;

  return {
    connectorId: CONNECTOR_ID,

    async init(scopedVaultSlice) {
      vaultSlice = scopedVaultSlice;
    },

    async selfTest() {
      return { ok: !!vaultSlice };
    },

    // payload: { sourceHost, method, body, runId, workflowManifestDigest, operation?, classification? }
    // sourceHost/method are checked against the contract's allowlist exactly
    // like outbound egress — default-deny applies to the direction data
    // crosses the trust boundary in, not just out.
    async send({ sourceHost, method, body, runId, workflowManifestDigest, operation = "governed-step.receive", classification }) {
      const bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
      const requestDigest = `sha256:${createHash("sha256").update(bodyBytes).digest("hex")}`;

      if (!assertEgressAllowed(contract, { host: sourceHost, method })) {
        recordEgress(db, { connectorId: CONNECTOR_ID, destinationHost: sourceHost, operation: method, decision: "blocked", requestDigest });
        throw new Error(`inbound-webhook blocked: ${method} from ${sourceHost} not in contract allowlist`);
      }
      recordEgress(db, { connectorId: CONNECTOR_ID, destinationHost: sourceHost, operation: method, decision: "allowed", requestDigest });

      const attestation = buildConnectorAttestation({
        runId,
        workflowManifestDigest,
        connectorId: CONNECTOR_ID,
        connectorVersion: CONNECTOR_VERSION,
        contractDigest,
        operation,
        scope: contract.scopes,
        endpointHost: sourceHost,
        payloadBytes: bodyBytes,
        classification,
      });

      return { attestation, payload: bodyBytes };
    },

    async dispose() {
      vaultSlice = null;
    },
  };
}
