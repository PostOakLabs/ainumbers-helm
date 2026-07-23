// Connector 1 (HELM-H6): google-drive.fetch — READ-ONLY. Retrieves a single
// Drive file's bytes via the OAuth token already in the vault (from H5's
// generic PKCE flow) and produces a signed connector_attestation. No writes,
// no other Drive scopes — matches the contract's drive.readonly scope.
//
// Lifecycle kept as init -> selfTest -> send -> dispose (borrowed shape, §4)
// even though "send" here means "perform the read": the borrowed contract is
// about the connector's calling convention, not the HTTP verb.
import { performEgress, buildConnectorAttestation } from "../connector.mjs";
import { vaultGet } from "../vault.mjs";

export const CONNECTOR_ID = "google-drive.fetch";
export const CONNECTOR_VERSION = "1.0.0";

export function createGoogleDriveFetchConnector({ db, contract, contractDigest }) {
  let vaultSlice = null;

  return {
    connectorId: CONNECTOR_ID,

    async init(scopedVaultSlice) {
      vaultSlice = scopedVaultSlice;
    },

    async selfTest() {
      if (!vaultSlice?.tokenRef) return { ok: false, reason: "no vault slice" };
      const token = vaultGet(vaultSlice.tokenRef);
      return { ok: !!token?.access_token };
    },

    // payload: { fileId, runId, workflowManifestDigest, classification? }
    async send({ fileId, runId, workflowManifestDigest, classification }) {
      const token = vaultGet(vaultSlice.tokenRef);
      if (!token?.access_token) throw new Error("google-drive.fetch: no access token in vault slice");

      const url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`;
      const result = await performEgress(db, {
        contract,
        connectorId: CONNECTOR_ID,
        url,
        method: "GET",
        headers: { Authorization: `Bearer ${token.access_token}` },
      });

      const attestation = buildConnectorAttestation({
        runId,
        workflowManifestDigest,
        connectorId: CONNECTOR_ID,
        connectorVersion: CONNECTOR_VERSION,
        contractDigest,
        operation: "drive.files.get",
        scope: contract.scopes,
        endpointHost: new URL(url).host,
        payloadBytes: result.body,
        classification,
      });

      return { attestation, payload: result.body };
    },

    async dispose() {
      vaultSlice = null;
    },
  };
}
