import { test } from "node:test";
import assert from "node:assert/strict";
import { buildMigrationBundle, digestEntries, submitMigrationToDaemon, BUNDLE_VERSION } from "./migration.mjs";

const NOW = new Date("2026-07-24T00:00:00.000Z");

function entries() {
  return [
    { kind: "run", run_id: "r1", period_start: "2026-07-01T00:00:00Z", period_end: "2026-07-01T00:00:01Z" },
    { kind: "run", run_id: "r2", period_start: "2026-07-02T00:00:00Z", period_end: "2026-07-02T00:00:01Z" },
  ];
}

function vaultRecord() {
  return { wrap_method: "webauthn-prf", wrapped_dek: "base64ciphertext==", kdf: { alg: "hkdf-sha256" } };
}

test("digestEntries: deterministic, one entry per seq, root chains all digests", async () => {
  const a = await digestEntries(entries());
  const b = await digestEntries(entries());
  assert.deepEqual(a, b);
  assert.equal(a.journalEntries.length, 2);
  assert.equal(a.journalEntries[0].seq, 0);
  assert.match(a.journalEntries[0].digest, /^sha256:[0-9a-f]{64}$/);
  assert.match(a.journalRootDigest, /^sha256:[0-9a-f]{64}$/);
});

test("digestEntries: changing one entry changes the root digest", async () => {
  const a = await digestEntries(entries());
  const mutated = entries();
  mutated[1].run_id = "tampered";
  const b = await digestEntries(mutated);
  assert.notEqual(a.journalRootDigest, b.journalRootDigest);
});

test("digestEntries: dropping an entry changes both entry list and root", async () => {
  const a = await digestEntries(entries());
  const b = await digestEntries(entries().slice(0, 1));
  assert.notEqual(a.journalEntries.length, b.journalEntries.length);
  assert.notEqual(a.journalRootDigest, b.journalRootDigest);
});

test("buildMigrationBundle: shape matches schema/migration_bundle.schema.json", async () => {
  const bundle = await buildMigrationBundle({
    entries: entries(),
    vaultRecord: vaultRecord(),
    sourceOrigin: "https://ainumbers.co",
    now: NOW,
  });
  assert.equal(bundle.bundle_version, BUNDLE_VERSION);
  assert.equal(bundle.source_origin, "https://ainumbers.co");
  assert.equal(bundle.exported_at, NOW.toISOString());
  assert.equal(bundle.journal_entries.length, 2);
  assert.match(bundle.journal_root_digest, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(bundle.vault_export, {
    wrap_method: "webauthn-prf",
    wrapped_dek: "base64ciphertext==",
    kdf: { alg: "hkdf-sha256" },
  });
  assert.equal(bundle.daemon_proof_required, true);
});

test("buildMigrationBundle: never carries the DEK or PRF output, only the wrapped record", async () => {
  const bundle = await buildMigrationBundle({
    entries: entries(),
    vaultRecord: vaultRecord(),
    sourceOrigin: "https://ainumbers.co",
    now: NOW,
  });
  const json = JSON.stringify(bundle);
  assert.doesNotMatch(json, /"dek"|"prf_output"|"passphrase"/i);
});

test("buildMigrationBundle: refuses a vaultRecord that isn't unlocked/enrolled", async () => {
  await assert.rejects(
    () => buildMigrationBundle({ entries: entries(), vaultRecord: null, sourceOrigin: "https://ainumbers.co", now: NOW }),
    /unlocked\/enrolled vault record/
  );
});

test("submitMigrationToDaemon: refuses to send without freshReauth === true", async () => {
  await assert.rejects(
    () => submitMigrationToDaemon({ bundle: {}, freshReauth: false, endpoint: "http://x", token: "t" }),
    /fresh re-auth/
  );
});

test("submitMigrationToDaemon: POSTs bundle + fresh_reauth, returns parsed body on success", async () => {
  let captured;
  const fetchImpl = async (url, opts) => {
    captured = { url, opts };
    return { ok: true, json: async () => ({ ok: true, markerSeq: 1 }) };
  };
  const bundle = await buildMigrationBundle({ entries: entries(), vaultRecord: vaultRecord(), sourceOrigin: "https://ainumbers.co", now: NOW });
  const result = await submitMigrationToDaemon({ bundle, freshReauth: true, endpoint: "http://127.0.0.1:4173/migration/import", token: "tok", fetchImpl });
  assert.equal(captured.url, "http://127.0.0.1:4173/migration/import");
  assert.equal(captured.opts.headers.Authorization, "Bearer tok");
  const sentBody = JSON.parse(captured.opts.body);
  assert.equal(sentBody.fresh_reauth, true);
  assert.deepEqual(sentBody.bundle, bundle);
  assert.deepEqual(result, { ok: true, markerSeq: 1 });
});

test("submitMigrationToDaemon: throws with the daemon's error on a non-ok response", async () => {
  const fetchImpl = async () => ({ ok: false, status: 422, json: async () => ({ error: "journal_root_digest_mismatch" }) });
  await assert.rejects(
    () => submitMigrationToDaemon({ bundle: {}, freshReauth: true, endpoint: "http://x", token: "t", fetchImpl }),
    /journal_root_digest_mismatch/
  );
});
