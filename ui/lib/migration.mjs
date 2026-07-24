// Browser-to-daemon migration bundle builder (P3-D10, HELM-P3-M7).
// OPFS journal entries + the browser vault's wrapped-DEK record never leave
// the browser except inside this bundle — the DEK itself never appears here
// (vault_export carries only what vault.mjs already produced: wrap_method +
// wrapped_dek + kdf, straight from the enrolled record). Building the bundle
// is NOT the proof step: P3-D9's signed-challenge daemon proof and the fresh
// WebAuthn/passphrase re-auth both happen in the caller, before/around this
// call — schema.daemon_proof_required just marks that contract, see
// schema/migration_bundle.schema.json.
import { cgCanon } from "./manifest-digest.mjs";

export const BUNDLE_VERSION = "1";

async function sha256Hex(bytes) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function entryBytes(entry) {
  return new TextEncoder().encode(JSON.stringify(cgCanon(entry)));
}

// One digest per journal entry, in append order (seq = 0-based position —
// matches the OPFS journal's own ordering, which has no separate seq field
// to preserve). journal_root_digest chains them so a single reordered,
// dropped, or edited entry changes the root (no-silent-loss gate, spec §5.5).
export async function digestEntries(entries) {
  const journalEntries = [];
  let rootInput = "";
  for (let seq = 0; seq < entries.length; seq++) {
    const digest = await sha256Hex(entryBytes(entries[seq]));
    journalEntries.push({ seq, digest: `sha256:${digest}` });
    rootInput += `${seq}:${digest}\n`;
  }
  const journalRootDigest = await sha256Hex(new TextEncoder().encode(rootInput));
  return { journalEntries, journalRootDigest: `sha256:${journalRootDigest}` };
}

// vaultRecord is exactly what ui/lib/vault.mjs's enroll*() produced/persisted
// — {wrap_method, wrapped_dek, kdf}. Passed through unchanged; this function
// never touches the DEK.
export async function buildMigrationBundle({ entries, vaultRecord, sourceOrigin, now = new Date() }) {
  if (!vaultRecord || !vaultRecord.wrap_method || !vaultRecord.wrapped_dek) {
    throw new Error("buildMigrationBundle: vaultRecord must be an unlocked/enrolled vault record");
  }
  const { journalEntries, journalRootDigest } = await digestEntries(entries);
  return {
    bundle_version: BUNDLE_VERSION,
    source_origin: sourceOrigin,
    exported_at: now.toISOString(),
    journal_entries: journalEntries,
    journal_root_digest: journalRootDigest,
    vault_export: {
      wrap_method: vaultRecord.wrap_method,
      wrapped_dek: vaultRecord.wrapped_dek,
      kdf: vaultRecord.kdf,
    },
    daemon_proof_required: true,
  };
}

// Triggers a same-tab download of the bundle as a .helm-migration.json file
// — the export-bundle path (P3-M7's "buildable" #1): carry-by-file to a
// freshly installed daemon with no live browser<->daemon connection needed.
export function offerMigrationBundleDownload(bundle, filename = `helm-migration-${Date.now()}.helm-migration.json`) {
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Daemon-mediated import path (P3-M7's "buildable" #2): POSTs the bundle
// directly to a paired daemon's /migration/import route. R15-F1/F2 fix:
// this used to gate on a bare `freshReauth === true` boolean the caller
// could set at any time or for any reason — no proof the daemon on the
// other end was ever verified, and no structural ordering. It now requires
// TWO things, checked structurally rather than trusted on the caller's say:
//   1. `verifiedChallenge` — the object returned by
//      ui/lib/challenge-browser.mjs's verifyPinnedChallenge(), i.e. a
//      signed daemon challenge that ALSO fingerprint-matched the pairing
//      link's pinned identity. A bare boolean can no longer stand in for
//      "the daemon proved itself."
//   2. `reauthAt` — the timestamp of a real, just-now WebAuthn/passphrase
//      unlock, which must be STRICTLY AFTER `verifiedChallenge.verifiedAt`.
//      This is P3-D9's "prove, THEN fresh-reauth, THEN send" order made
//      structural: the send is refused if reauth happened before (or
//      without reference to) the daemon proof, not just documented as a
//      comment the caller could ignore.
// R15-F6: the daemon's /migration/import route (hub/server.mjs's
// handleMigrationImport) proves continuity by recomputing digests over the
// RAW entries and comparing them to the bundle's manifest (hub/migration-
// import.mjs's verifyBundleContinuity) — the manifest alone (seq+digest per
// entry) is never enough, the route 400s with missing_bundle_or_raw_entries
// without the raw entries riding alongside it. entries: the SAME array
// passed to buildMigrationBundle()'s digestEntries() for this bundle — this
// function does not re-derive or validate that correspondence, the daemon's
// continuity check is what proves it. fetchImpl is injectable so this stays
// node:test-able without a real browser.
export async function submitMigrationToDaemon({ bundle, entries, verifiedChallenge, reauthAt, endpoint, token, overwrite = false, fetchImpl = fetch }) {
  if (!verifiedChallenge || typeof verifiedChallenge !== "object" || !verifiedChallenge.fingerprint || typeof verifiedChallenge.verifiedAt !== "number") {
    throw new Error("submitMigrationToDaemon: refusing to send vault material without a verified, pinned daemon challenge");
  }
  if (typeof reauthAt !== "number" || reauthAt <= verifiedChallenge.verifiedAt) {
    throw new Error("submitMigrationToDaemon: refusing to send — fresh re-auth must happen AFTER the daemon proof, not before");
  }
  if (!Array.isArray(entries)) {
    throw new Error("submitMigrationToDaemon: entries (the raw journal entries this bundle's manifest was built from) is required");
  }
  const res = await fetchImpl(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ bundle, raw_entries: entries, fresh_reauth: true, overwrite }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`migration import failed: ${body.error || res.status}`);
  return body;
}
