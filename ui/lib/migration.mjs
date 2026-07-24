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
// directly to a paired daemon's /migration/import route. `freshReauth` must
// be true — the caller only sets it after a real, just-now WebAuthn/
// passphrase unlock succeeded (P3-D9 ordering: AFTER the daemon has already
// proven itself via the signed-challenge probe, never before). fetchImpl is
// injectable so this stays node:test-able without a real browser.
export async function submitMigrationToDaemon({ bundle, freshReauth, endpoint, token, fetchImpl = fetch }) {
  if (freshReauth !== true) {
    throw new Error("submitMigrationToDaemon: refusing to send vault material without a fresh re-auth");
  }
  const res = await fetchImpl(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify({ bundle, fresh_reauth: true }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(`migration import failed: ${body.error || res.status}`);
  return body;
}
