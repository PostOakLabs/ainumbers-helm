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

function verifiedChallenge(verifiedAt = 1000) {
  return { nonce: "n", signature: "s", publicKey: "pk", fingerprint: "sha256:abc", verifiedAt };
}

test("submitMigrationToDaemon: refuses to send without a verified+pinned challenge object", async () => {
  await assert.rejects(
    () => submitMigrationToDaemon({ bundle: {}, verifiedChallenge: null, reauthAt: 2000, endpoint: "http://x", token: "t" }),
    /verified, pinned daemon challenge/
  );
});

test("submitMigrationToDaemon: refuses a bare-boolean stand-in (R15-F2 regression guard — the old freshReauth:true shape must not satisfy the new gate)", async () => {
  await assert.rejects(
    () => submitMigrationToDaemon({ bundle: {}, verifiedChallenge: true, reauthAt: 2000, endpoint: "http://x", token: "t" }),
    /verified, pinned daemon challenge/
  );
});

test("submitMigrationToDaemon: refuses when reauthAt is BEFORE the daemon proof (ordering enforced structurally)", async () => {
  await assert.rejects(
    () => submitMigrationToDaemon({ bundle: {}, verifiedChallenge: verifiedChallenge(2000), reauthAt: 1000, endpoint: "http://x", token: "t" }),
    /AFTER the daemon proof/
  );
});

test("submitMigrationToDaemon: refuses when reauthAt exactly equals verifiedAt (must be strictly after)", async () => {
  await assert.rejects(
    () => submitMigrationToDaemon({ bundle: {}, verifiedChallenge: verifiedChallenge(1000), reauthAt: 1000, endpoint: "http://x", token: "t" }),
    /AFTER the daemon proof/
  );
});

test("submitMigrationToDaemon: wired happy path — verified-pinned challenge, THEN reauth, THEN send — POSTs bundle + fresh_reauth, returns parsed body", async () => {
  let captured;
  const fetchImpl = async (url, opts) => {
    captured = { url, opts };
    return { ok: true, json: async () => ({ ok: true, markerSeq: 1 }) };
  };
  const bundle = await buildMigrationBundle({ entries: entries(), vaultRecord: vaultRecord(), sourceOrigin: "https://ainumbers.co", now: NOW });
  const result = await submitMigrationToDaemon({
    bundle,
    verifiedChallenge: verifiedChallenge(1000),
    reauthAt: 2000,
    endpoint: "http://127.0.0.1:4173/migration/import",
    token: "tok",
    fetchImpl,
  });
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
    () =>
      submitMigrationToDaemon({
        bundle: {},
        verifiedChallenge: verifiedChallenge(1000),
        reauthAt: 2000,
        endpoint: "http://x",
        token: "t",
        fetchImpl,
      }),
    /journal_root_digest_mismatch/
  );
});
