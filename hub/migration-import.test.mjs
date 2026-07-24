// Round-trip + no-silent-loss tests for P3-M7 (HELM-PHASE3-BUILD-SPEC.md §5
// gate 5): build a real bundle with the browser-side builder, import it on
// the daemon side, verify the journal chain and vault land intact — then
// prove the same import is REFUSED on a tampered/incomplete transfer.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-migration-test-"));
process.env.HELM_HOME = TMP;

const { buildMigrationBundle } = await import("../ui/lib/migration.mjs");
const { openJournal, replayVerify } = await import("./journal.mjs");
const { importMigrationBundle, verifyBundleContinuity } = await import("./migration-import.mjs");
const { vaultGet } = await import("./vault.mjs");

function rawEntries() {
  return [
    { kind: "run", run_id: "r1", note: "first browser-mode run" },
    { kind: "run", run_id: "r2", note: "second browser-mode run" },
    { kind: "run", run_id: "r3", note: "third browser-mode run" },
  ];
}

function vaultRecord() {
  return { wrap_method: "webauthn-prf", wrapped_dek: "b64-wrapped-dek==", kdf: { alg: "hkdf-sha256" } };
}

// Every test uses its OWN source_origin — the vault store is keyed globally
// under one shared HELM_HOME for this whole file, so reusing an origin across
// tests would let one test's successful vaultSet leak into another's
// "nothing was written" assertion.

test("round trip: browser data -> daemon import -> verifies, no silent loss", async () => {
  const origin = "https://ainumbers.co.roundtrip.test";
  const db = openJournal(join(TMP, "roundtrip.db"));
  const entries = rawEntries();
  const bundle = await buildMigrationBundle({
    entries,
    vaultRecord: vaultRecord(),
    sourceOrigin: origin,
    now: new Date("2026-07-24T00:00:00.000Z"),
  });

  const result = importMigrationBundle(db, { bundle, rawEntries: entries, freshReauth: true });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(typeof result.markerSeq, "number");
  assert.equal(result.vaultRef, `migrated-vault:${origin}`);

  // journal chain continuity preserved across migration
  assert.equal(replayVerify(db).ok, true);

  // migrated-from marker present with the imported count + source
  const markerRow = db.prepare("SELECT entry_json FROM journal WHERE stream_id = ?").get(result.streamId);
  const marker = JSON.parse(markerRow.entry_json);
  assert.equal(marker.kind, "migration_import");
  assert.equal(marker.imported_entry_count, 3);
  assert.equal(marker.source_origin, origin);

  // vault material landed, still wrapped (never a raw DEK/PRF/passphrase)
  const storedVault = vaultGet(result.vaultRef);
  assert.deepEqual(storedVault, bundle.vault_export);

  db.close();
});

test("no-silent-loss: a dropped entry is caught before anything is written", async () => {
  const origin = "https://ainumbers.co.dropped.test";
  const db = openJournal(join(TMP, "dropped.db"));
  const entries = rawEntries();
  const bundle = await buildMigrationBundle({ entries, vaultRecord: vaultRecord(), sourceOrigin: origin });

  const result = importMigrationBundle(db, { bundle, rawEntries: entries.slice(0, 2), freshReauth: true });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "entry_count_mismatch");
  assert.equal(replayVerify(db).ok, true); // nothing partially written
  assert.equal(vaultGet(`migrated-vault:${origin}`), null);
  db.close();
});

test("no-silent-loss: a tampered entry (same count) is caught via digest mismatch", async () => {
  const origin = "https://ainumbers.co.tampered.test";
  const db = openJournal(join(TMP, "tampered.db"));
  const entries = rawEntries();
  const bundle = await buildMigrationBundle({ entries, vaultRecord: vaultRecord(), sourceOrigin: origin });

  const tampered = rawEntries();
  tampered[1].note = "silently edited after export";
  const result = importMigrationBundle(db, { bundle, rawEntries: tampered, freshReauth: true });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "entry_digest_mismatch");
  assert.equal(vaultGet(`migrated-vault:${origin}`), null);
  db.close();
});

test("refuses import without a fresh re-auth, even with a perfectly valid bundle", async () => {
  const origin = "https://ainumbers.co.noreauth.test";
  const db = openJournal(join(TMP, "noreauth.db"));
  const entries = rawEntries();
  const bundle = await buildMigrationBundle({ entries, vaultRecord: vaultRecord(), sourceOrigin: origin });
  const result = importMigrationBundle(db, { bundle, rawEntries: entries, freshReauth: false });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "fresh_reauth_required");
  assert.equal(vaultGet(`migrated-vault:${origin}`), null);
  db.close();
});

test("verifyBundleContinuity: schema violation is reported, not thrown", async () => {
  const entries = rawEntries();
  const bundle = await buildMigrationBundle({ entries, vaultRecord: vaultRecord(), sourceOrigin: "https://ainumbers.co.schema.test" });
  const broken = { ...bundle, bundle_version: "2" }; // schema requires const "1"
  const result = verifyBundleContinuity(broken, entries);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "schema");
});

after(() => rmSync(TMP, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
