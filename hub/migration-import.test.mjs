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

// R15-F8: source_origin is attacker-controlled, so `migrated-vault:${source_
// origin}` is a ref an attacker can pick to collide with a prior migration
// and silently clobber someone else's wrapped vault material. These two
// tests prove: (1) a retried import of the SAME bundle is idempotent, no
// duplicate marker/overwrite, and (2) a DIFFERENT bundle claiming the same
// source_origin is refused unless the caller explicitly passes overwrite:true.
test("R15-F8: retrying the SAME bundle import is idempotent — no duplicate marker, no re-write", async () => {
  const origin = "https://ainumbers.co.idempotent.test";
  const db = openJournal(join(TMP, "idempotent.db"));
  const entries = rawEntries();
  const bundle = await buildMigrationBundle({ entries, vaultRecord: vaultRecord(), sourceOrigin: origin, now: new Date("2026-07-24T00:00:00.000Z") });

  const first = importMigrationBundle(db, { bundle, rawEntries: entries, freshReauth: true });
  assert.equal(first.ok, true);
  assert.equal(first.idempotent, undefined);

  const second = importMigrationBundle(db, { bundle, rawEntries: entries, freshReauth: true });
  assert.equal(second.ok, true);
  assert.equal(second.idempotent, true);
  assert.equal(second.markerSeq, first.markerSeq);

  const markerRows = db.prepare("SELECT entry_json FROM journal WHERE stream_id = ? AND kind = ?").all(first.streamId, "migration_import");
  assert.equal(markerRows.length, 1, "a retried import must not append a second marker");
  assert.equal(replayVerify(db).ok, true);
  db.close();
});

test("R15-F8: a DIFFERENT bundle claiming the same source_origin is refused, not silently overwritten", async () => {
  const origin = "https://ainumbers.co.collision.test";
  const db = openJournal(join(TMP, "collision.db"));
  const firstEntries = rawEntries();
  const firstBundle = await buildMigrationBundle({ entries: firstEntries, vaultRecord: vaultRecord(), sourceOrigin: origin, now: new Date("2026-07-24T00:00:00.000Z") });
  const firstResult = importMigrationBundle(db, { bundle: firstBundle, rawEntries: firstEntries, freshReauth: true });
  assert.equal(firstResult.ok, true);
  const storedBefore = vaultGet(`migrated-vault:${origin}`);
  assert.deepEqual(storedBefore, firstBundle.vault_export);

  // A different bundle (different vault_export, different journal contents)
  // asserting the SAME source_origin — an attacker could pick this on purpose.
  const attackerEntries = [{ kind: "run", run_id: "attacker-r1", note: "attacker-controlled" }];
  const attackerBundle = await buildMigrationBundle({
    entries: attackerEntries,
    vaultRecord: { wrap_method: "webauthn-prf", wrapped_dek: "attacker-b64==", kdf: { alg: "hkdf-sha256" } },
    sourceOrigin: origin,
    now: new Date("2026-07-24T01:00:00.000Z"),
  });
  const refused = importMigrationBundle(db, { bundle: attackerBundle, rawEntries: attackerEntries, freshReauth: true });
  assert.equal(refused.ok, false);
  assert.equal(refused.reason, "vault_ref_exists");
  assert.deepEqual(vaultGet(`migrated-vault:${origin}`), storedBefore, "existing vault material must be untouched");

  // Explicit overwrite:true is honored.
  const overwritten = importMigrationBundle(db, { bundle: attackerBundle, rawEntries: attackerEntries, freshReauth: true, overwrite: true });
  assert.equal(overwritten.ok, true);
  assert.deepEqual(vaultGet(`migrated-vault:${origin}`), attackerBundle.vault_export);
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
