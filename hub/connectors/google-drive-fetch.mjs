// Connector 1 (HELM-H6, scope migrated HELM-P3-U4/P3-D5): google-drive.fetch.
// Retrieves a single Drive file's bytes via the OAuth token already in the
// vault (from H5's generic PKCE flow) and produces a signed
// connector_attestation. Read-only HTTP verb (GET) only — no write calls —
// against the contract's `drive.file` scope: drive.readonly and the bare
// `drive` scope are both Google RESTRICTED scopes requiring an annual CASA
// assessment ($500-4.5k/yr), dead at $0 budget (P3-D5/P3-DEC-2, locked
// 2026-07-23). drive.file only grants access to files the user explicitly
// opened/created through this app, which is what the caller of send() is
// expected to already have (a fileId the user picked), so this connector's
// own behavior is unchanged by the migration.
//
// Lifecycle kept as init -> selfTest -> send -> dispose (borrowed shape, §4)
// even though "send" here means "perform the read": the borrowed contract is
// about the connector's calling convention, not the HTTP verb.
//
// HELM-P2-H9a: the token is never read into this module's own scope — it
// passes a vault ref to performEgress, which resolves+attaches it at the
// egress boundary via credential-provider.mjs.
import { performEgress, buildConnectorAttestation } from "../connector.mjs";
import { credentialExists } from "../credential-provider.mjs";

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
      return { ok: credentialExists(vaultSlice.tokenRef) };
    },

    // payload: { fileId, runId, workflowManifestDigest, classification? }
    async send({ fileId, runId, workflowManifestDigest, classification }) {
      if (!vaultSlice?.tokenRef) throw new Error("google-drive.fetch: no vault slice");

      const url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`;
      const result = await performEgress(db, {
        contract,
        connectorId: CONNECTOR_ID,
        url,
        method: "GET",
        credential: { ref: vaultSlice.tokenRef, scheme: "bearer" },
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
