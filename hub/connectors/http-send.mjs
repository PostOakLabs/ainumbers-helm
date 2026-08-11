// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Connector 3 (HELM-P2-H9b): http.send — generic pure-config outbound HTTP
// (API-key or bearer auth). Unlike google-drive.fetch (one hardcoded
// endpoint baked into the module), this connector's TARGET is the contract:
// operators copy http-send.contract.json, fill in their own allowed_hosts/
// allowed_methods/vault_scope, and pass the loaded contract in at
// construction. The connector code itself never hardcodes a host.
//
// Routes through connector.mjs's performEgress unchanged — same DNS-
// resolved-IP deny-list guard, same manual-redirect re-check per hop, same
// egress journal — so http.send gets the H9a hardening for free.
import { performEgress, buildConnectorAttestation } from "../connector.mjs";
import { credentialExists } from "../credential-provider.mjs";
import { signWebhookPayload } from "../webhook-signing.mjs";

export const CONNECTOR_ID = "http.send";
export const CONNECTOR_VERSION = "1.0.0";

export function createHttpConnector({ db, contract, contractDigest }) {
  let vaultSlice = null;

  return {
    connectorId: CONNECTOR_ID,

    async init(scopedVaultSlice) {
      vaultSlice = scopedVaultSlice;
    },

    async selfTest() {
      if (!vaultSlice?.credentialRef) return { ok: true, reason: "no credential configured (unauthenticated target)" };
      return { ok: credentialExists(vaultSlice.credentialRef) };
    },

    // payload: { url, method, headers?, body?, credentialScheme?, runId,
    //   workflowManifestDigest, operation?, classification?, signingSecret? }
    // credentialScheme: "bearer" (default) | "basic" | "api-key-header" —
    // see credential-provider.mjs; ignored if no credentialRef is configured.
    // signingSecret (HELM-PUSH-HMAC-1): when set, the delivery is signed
    // Stripe-webhook-shape and the signature rides in the Helm-Signature
    // header — "t=<unix_ts>,v1=<hmac_sha256(secret, ts + '.' + body)>".
    // Opt-in: omit to send unsigned, unchanged from before this row.
    async send({ url, method, headers = {}, body = null, credentialScheme = "bearer", runId, workflowManifestDigest, operation = "http.send", classification, signingSecret }) {
      if (!vaultSlice) throw new Error("http.send: connector not initialized");
      const credential = vaultSlice.credentialRef ? { ref: vaultSlice.credentialRef, scheme: credentialScheme } : null;
      const sentHeaders = signingSecret && body != null
        ? { ...headers, "Helm-Signature": signWebhookPayload(signingSecret, body) }
        : headers;

      const result = await performEgress(db, {
        contract,
        connectorId: CONNECTOR_ID,
        url,
        method,
        headers: sentHeaders,
        body,
        credential,
      });

      const attestation = buildConnectorAttestation({
        runId,
        workflowManifestDigest,
        connectorId: CONNECTOR_ID,
        connectorVersion: CONNECTOR_VERSION,
        contractDigest,
        operation,
        scope: contract.scopes,
        endpointHost: new URL(url).host,
        payloadBytes: result.body,
        classification,
      });

      return { attestation, payload: result.body, status: result.status };
    },

    async dispose() {
      vaultSlice = null;
    },
  };
}
