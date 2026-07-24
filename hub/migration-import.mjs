// Daemon-side migration import (P3-D10, HELM-P3-M7). A migration_bundle
// (schema/migration_bundle.schema.json, shipped by P3-S1) is a signed-free
// continuity MANIFEST — seq+digest per browser journal entry, plus the
// chained root — not the entries themselves. The raw entries travel
// alongside it (export-bundle file, or the daemon-mediated POST body) and
// this module's first job is proving the two agree before anything is
// written: a manifest with no matching raw data is not a migration, it's an
// unverifiable claim.
//
// This module never re-derives or checks the P3-D9 signed-challenge proof or
// the fresh WebAuthn/passphrase re-auth — those happen in the browser/route
// layer, strictly before this runs (P3-D9 ordering). Its own gate is
// `freshReauth === true`, a structural refusal if the caller skipped that
// step, not a cryptographic verification of it (no server-side WebAuthn
// verifier exists in this zero-dep daemon — the paired bearer token is
// already the trust boundary for everything reachable through this route).
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { appendEntry, replayVerify } from "./journal.mjs";
import { vaultSet, vaultGet } from "./vault.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MIGRATION_SCHEMA = JSON.parse(readFileSync(join(HERE, "..", "schema", "migration_bundle.schema.json"), "utf8"));
const MIGRATION_STREAM_PREFIX = "migrated-from:";

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function entryBytes(entry) {
  assertIJson(entry);
  return Buffer.from(JSON.stringify(cgCanon(entry)), "utf8");
}

// Mirrors ui/lib/migration.mjs's digestEntries() exactly — same seq scheme
// (0-based append order), same "seq:digest\n" root-chaining — so a
// browser-built bundle and a daemon-recomputed one agree byte for byte with
// nothing else in the loop.
export function digestRawEntries(rawEntries) {
  const journalEntries = [];
  let rootInput = "";
  rawEntries.forEach((entry, seq) => {
    const digest = sha256Hex(entryBytes(entry));
    journalEntries.push({ seq, digest: `sha256:${digest}` });
    rootInput += `${seq}:${digest}\n`;
  });
  const journalRootDigest = `sha256:${sha256Hex(Buffer.from(rootInput, "utf8"))}`;
  return { journalEntries, journalRootDigest };
}

// The no-silent-loss check (spec §5 gate 5): the raw entries actually
// present must reproduce, byte for byte, the manifest the browser signed
// off on — count, per-entry digest, and chained root all have to agree.
export function verifyBundleContinuity(bundle, rawEntries) {
  const schemaErrors = validate(MIGRATION_SCHEMA, bundle);
  if (schemaErrors.length) return { ok: false, reason: "schema", errors: schemaErrors };
  if (!Array.isArray(rawEntries) || rawEntries.length !== bundle.journal_entries.length) {
    return {
      ok: false,
      reason: "entry_count_mismatch",
      expected: bundle.journal_entries.length,
      got: Array.isArray(rawEntries) ? rawEntries.length : 0,
    };
  }
  const recomputed = digestRawEntries(rawEntries);
  if (JSON.stringify(recomputed.journalEntries) !== JSON.stringify(bundle.journal_entries)) {
    return { ok: false, reason: "entry_digest_mismatch" };
  }
  if (recomputed.journalRootDigest !== bundle.journal_root_digest) {
    return { ok: false, reason: "journal_root_digest_mismatch" };
  }
  return { ok: true, reason: null };
}

// R15-F8: source_origin is attacker-controlled (it's the caller's own claim,
// not anything the daemon independently verified), so `migrated-vault:${source_
// origin}` is a ref an attacker can pick to collide with a prior migration's
// ref and silently clobber someone else's vault material. Finds the existing
// migration_import marker (if any) for this stream by re-scanning its
// journal rows — cheap: one migration stream per source_origin, imports are
// rare — rather than adding a query surface just for this check.
function findExistingMarker(db, streamId, journalRootDigest) {
  const rows = db.prepare("SELECT seq, entry_json FROM journal WHERE stream_id = ? AND kind = ?").all(streamId, "migration_import");
  for (const row of rows) {
    const entry = JSON.parse(row.entry_json);
    if (entry.triggering_input_digest === journalRootDigest) return { seq: row.seq, entry };
  }
  return null;
}

// Verifies continuity, stores the still-wrapped vault material (never
// unwrapped here — no PRF/passphrase key reaches the daemon, ever), and
// leaves a migrated-from marker in the HUB's own journal chain. "journal
// chain continuity preserved across migration" means the hub's own
// running-hash chain stays verifiable after the marker append (checked below
// via replayVerify) — the browser's entries are not spliced into the hub's
// per-stream hash chain, they're proven-then-recorded as evidence under
// their own migration stream.
//
// R15-F8: append is idempotent on (source_origin, journal_root_digest) — a
// retried import of the SAME bundle (network hiccup, client retry) returns
// the existing marker rather than appending a duplicate. A DIFFERENT bundle
// claiming the same source_origin (attacker-controlled) refuses to overwrite
// the existing vault ref unless the caller explicitly passes overwrite:true.
export function importMigrationBundle(db, { bundle, rawEntries, freshReauth, overwrite = false }) {
  if (freshReauth !== true) {
    return { ok: false, reason: "fresh_reauth_required" };
  }
  const continuity = verifyBundleContinuity(bundle, rawEntries);
  if (!continuity.ok) return { ok: false, ...continuity };

  const streamId = `${MIGRATION_STREAM_PREFIX}${bundle.source_origin}`;
  const existing = findExistingMarker(db, streamId, bundle.journal_root_digest);
  if (existing) {
    const vaultRef = `migrated-vault:${bundle.source_origin}`;
    return { ok: true, reason: null, markerSeq: existing.seq, vaultRef, streamId, idempotent: true };
  }

  const vaultRef = `migrated-vault:${bundle.source_origin}`;
  if (!overwrite && vaultGet(vaultRef) !== null) {
    return { ok: false, reason: "vault_ref_exists", vaultRef };
  }
  vaultSet(vaultRef, bundle.vault_export);

  const marker = appendEntry(db, {
    streamId,
    kind: "migration_import",
    entry: {
      period_start: bundle.exported_at,
      period_end: bundle.exported_at,
      reference_db_version: "n/a",
      triggering_input_digest: bundle.journal_root_digest,
      humans_involved: [],
      source_origin: bundle.source_origin,
      bundle_version: bundle.bundle_version,
      imported_entry_count: rawEntries.length,
      vault_ref: vaultRef,
    },
  });

  const replay = replayVerify(db);
  if (!replay.ok) {
    // Should be unreachable — appendEntry is chain-safe by construction —
    // but a broken chain post-import is exactly the failure this gate
    // exists to catch, so report it rather than a false ok:true.
    return { ok: false, reason: "post_import_chain_broken", brokenAt: replay.brokenAt };
  }

  return { ok: true, reason: null, markerSeq: marker.seq, vaultRef, streamId };
}
