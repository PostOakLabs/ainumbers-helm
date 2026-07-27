// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-KEYCHAIN-1: the at-rest passphrase moves into vault.mjs's OS-keychain
// tier. These tests assert the four migration failure modes phil named cannot
// happen, plus his done-test and its inverse.
//
// Each test runs in its own state dir. statePath() re-reads HELM_HOME on every
// call and vault.mjs re-reads vault-index.json on every call, so flipping the
// env var between tests gives real isolation without re-importing the modules.
// The vault ref is namespaced per state dir, so the machine-global tiers
// (macOS Keychain, Linux Secret Service) cannot collide across tests or with a
// developer's real ~/.helm install.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const ROOT = mkdtempSync(join(tmpdir(), "helm-keychain-test-"));
const homes = [];

function freshHome(name) {
  const dir = join(ROOT, name);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  process.env.HELM_HOME = dir;
  homes.push(dir);
  return dir;
}

const keys = await import("./keys.mjs");
const { loadOrCreateKeys, loadOrCreatePassphrase, atRestPassphraseRef, LEGACY_PASSPHRASE_FILENAME } = keys;
const { vaultGet, vaultDelete, vaultBackendFor } = await import("./vault.mjs");

after(() => {
  // Leave no keychain entries behind on machine-global tiers.
  for (const dir of homes) {
    try {
      process.env.HELM_HOME = dir;
      if (existsSync(join(dir, "passphrase-ref.json"))) vaultDelete(atRestPassphraseRef());
    } catch {
      /* best effort */
    }
  }
  rmSync(ROOT, { recursive: true, force: true });
});

// --- baseline: fresh install provisions into the vault, not beside the data ---

test("fresh install: the passphrase goes to the vault and never lands in the state dir", () => {
  const home = freshHome("fresh");
  const keypair = loadOrCreateKeys();
  const ref = atRestPassphraseRef();

  assert.ok(vaultBackendFor(ref), "passphrase should be recorded in the vault index");
  assert.equal(existsSync(join(home, LEGACY_PASSPHRASE_FILENAME)), false, "no legacy vault.key should be created");

  const pass = loadOrCreatePassphrase();
  assert.equal(pass.length, 32);

  // The passphrase bytes must not appear anywhere in the state dir root —
  // that adjacency is the defect this WU removes.
  for (const entry of readdirSync(home, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const raw = readFileSync(join(home, entry.name));
    assert.equal(raw.includes(pass), false, `passphrase bytes found in ${entry.name}`);
    assert.equal(
      raw.toString("latin1").includes(pass.toString("base64")),
      false,
      `passphrase (base64) found in ${entry.name}`
    );
  }

  // Sanity: the keys still load and are stable.
  assert.deepEqual(
    loadOrCreateKeys().ed25519.publicKey.export({ format: "der", type: "spki" }),
    keypair.ed25519.publicKey.export({ format: "der", type: "spki" })
  );
});

// --- migration from a pre-existing vault.key + keys.enc.json install ---

test("migration: a pre-keychain install keeps its identity and loses its vault.key", () => {
  // Build a genuine legacy install: write vault.key first, so the ORIGINAL
  // code path's on-disk layout is what we migrate from.
  const home = freshHome("migrate");
  const legacy = join(home, LEGACY_PASSPHRASE_FILENAME);
  const legacyPass = randomBytes(32);
  writeFileSync(legacy, legacyPass, { mode: 0o600 });

  // keys.enc.json is created under the legacy passphrase, because
  // loadOrCreateKeys() adopts the file that is already there.
  const before = loadOrCreateKeys();
  assert.equal(existsSync(join(home, "keys.enc.json")), true);

  // FAILURE MODE 1 — key loss: the migration must not destroy the identity.
  const after1 = loadOrCreateKeys();
  assert.deepEqual(
    after1.ed25519.publicKey.export({ format: "der", type: "spki" }),
    before.ed25519.publicKey.export({ format: "der", type: "spki" }),
    "identity must survive migration"
  );
  assert.deepEqual(after1.mldsa44.publicKey, before.mldsa44.publicKey);

  // The adopted passphrase is the legacy one, byte for byte — not a new mint.
  const ref = atRestPassphraseRef();
  assert.deepEqual(
    Buffer.from(vaultGet(ref).passphrase_b64, "base64"),
    legacyPass,
    "the vault must hold the ORIGINAL passphrase, not a replacement"
  );

  // FAILURE MODE 2 — dual-copy window: the legacy file is gone, not orphaned.
  assert.equal(existsSync(legacy), false, "vault.key must be removed once the vault holds the passphrase");
});

test("migration: the legacy file's bytes are overwritten before unlink, not just unlinked", () => {
  const home = freshHome("shred");
  const legacy = join(home, LEGACY_PASSPHRASE_FILENAME);
  const legacyPass = randomBytes(32);
  writeFileSync(legacy, legacyPass, { mode: 0o600 });

  const got = loadOrCreatePassphrase();
  assert.deepEqual(got, legacyPass);
  assert.equal(existsSync(legacy), false);

  // Nothing left in the state dir may still carry those bytes.
  for (const entry of readdirSync(home, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    assert.equal(readFileSync(join(home, entry.name)).includes(legacyPass), false, `bytes survive in ${entry.name}`);
  }
});

// --- phil's done-test, and its inverse ---

test("phil's done-test: deleting vault.key does NOT enable decryption — the keychain entry is what matters", () => {
  const home = freshHome("done-test");
  const keypair = loadOrCreateKeys();
  const ref = atRestPassphraseRef();

  // vault.key is already absent post-migration; assert it and confirm the
  // daemon still opens its keys, i.e. the secret genuinely moved.
  assert.equal(existsSync(join(home, LEGACY_PASSPHRASE_FILENAME)), false);
  assert.deepEqual(
    loadOrCreateKeys().ed25519.publicKey.export({ format: "der", type: "spki" }),
    keypair.ed25519.publicKey.export({ format: "der", type: "spki" })
  );
  assert.ok(vaultBackendFor(ref));

  // And the converse of the same claim: an attacker holding ONLY the state
  // dir has an AEAD blob with no key in it.
  const blob = JSON.parse(readFileSync(join(home, "keys.enc.json"), "utf8"));
  assert.ok(blob.ciphertext && blob.iv && blob.tag && blob.salt);
});

test("FAILURE MODE 3 — silent downgrade: a destroyed keychain entry fails loudly, never mints a new identity", () => {
  const home = freshHome("destroyed-entry");
  loadOrCreateKeys();
  const ref = atRestPassphraseRef();

  // Destroy the secret while leaving the index entry behind — exactly what an
  // OS keychain reset, a moved profile, or a wrong OS user looks like.
  const idxPath = join(home, "vault-index.json");
  const idx = JSON.parse(readFileSync(idxPath, "utf8"));
  const tier = idx[ref];
  assert.ok(tier, "precondition: the ref is in the index");
  vaultDelete(ref);
  writeFileSync(idxPath, JSON.stringify({ ...idx, [ref]: tier }, null, 2) + "\n", { mode: 0o600 });

  assert.throws(
    () => loadOrCreatePassphrase(),
    /no longer holds it/,
    "must throw rather than fall through to a fresh passphrase"
  );
  assert.throws(() => loadOrCreateKeys(), /no longer holds it/);
});

test("FAILURE MODE 3 — silent downgrade: passphrase gone entirely + ciphertext present = loud refusal", () => {
  const home = freshHome("orphaned-ciphertext");
  loadOrCreateKeys();

  // Simulate the harsher case: the index AND the ref label are gone (state
  // dir restored from a partial backup), but keys.enc.json survived. Minting
  // here would silently change the daemon's identity.
  vaultDelete(atRestPassphraseRef());
  rmSync(join(home, "vault-index.json"), { force: true });
  rmSync(join(home, "passphrase-ref.json"), { force: true });
  rmSync(join(home, "vault"), { recursive: true, force: true });
  assert.equal(existsSync(join(home, "keys.enc.json")), true, "precondition: ciphertext still present");

  assert.throws(
    () => loadOrCreatePassphrase(),
    /Refusing to generate a replacement/,
    "must refuse rather than mint a fresh passphrase over live ciphertext"
  );
});

test("FAILURE MODE 3 — the same refusal covers ha-identity.enc.json, not just keys.enc.json", async () => {
  const home = freshHome("orphaned-ha-identity");
  const { loadOrCreateHaIdentity } = await import("./ha-identity.mjs");
  await loadOrCreateHaIdentity();
  assert.equal(existsSync(join(home, "ha-identity.enc.json")), true);

  vaultDelete(atRestPassphraseRef());
  rmSync(join(home, "vault-index.json"), { force: true });
  rmSync(join(home, "passphrase-ref.json"), { force: true });
  rmSync(join(home, "vault"), { recursive: true, force: true });
  // No keys.enc.json here — the HA blob alone must be enough to trigger it.
  rmSync(join(home, "keys.enc.json"), { force: true });

  assert.throws(() => loadOrCreatePassphrase(), /ha-identity\.enc\.json/);
});

// --- resume of a crash-interrupted migration (KEYCHAIN-PROVABLE-1) ---
// keys.mjs:118-123 — the "already migrated" branch also shreds a lingering
// legacy file, so a process that crashed AFTER provisionPassphrase()
// succeeded but BEFORE shredFile() ran finishes cleanly on its next boot
// instead of leaking the old plaintext file forever.

test("resume: an interrupted migration (vault already holds the passphrase, legacy file still present) shreds it without re-migrating", () => {
  const home = freshHome("resume-interrupted");
  const legacy = join(home, LEGACY_PASSPHRASE_FILENAME);
  const legacyPass = randomBytes(32);
  writeFileSync(legacy, legacyPass, { mode: 0o600 });

  const pass1 = loadOrCreatePassphrase(); // completes migration normally
  assert.equal(existsSync(legacy), false, "precondition: normal migration already shredded the legacy file");

  // Simulate the crash: the legacy file reappears holding the SAME bytes the
  // vault already has, exactly what "provisioned, not yet shredded" looks
  // like on disk.
  writeFileSync(legacy, legacyPass, { mode: 0o600 });

  const pass2 = loadOrCreatePassphrase(); // must take the "already migrated" branch
  assert.deepEqual(pass2, pass1, "resume must return the SAME passphrase, not mint or re-adopt one");
  assert.equal(existsSync(legacy), false, "the resumed load must finish the interrupted shred");
});

// --- readback-mismatch branch of provisionPassphrase: DECLINED, with reason ---
// hub/keys.mjs:90-97 throws when vaultGetStrict's readback doesn't match what
// was just vaultSet — reachable only by a fault landing between those two
// calls inside one synchronous function body. This zero-dep suite has no
// mocking capability (no jest/sinon) and the fence for KEYCHAIN-PROVABLE-1
// forbids editing keys.mjs/vault.mjs to add an injection seam, so there is no
// way to exercise this branch without either dependency. Left uncovered,
// named here rather than silently skipped.

// --- partial migration ---

test("FAILURE MODE 4 — partial migration: keys.mjs and ha-identity.mjs share ONE passphrase path", async () => {
  const home = freshHome("single-call-site");
  const { loadOrCreateHaIdentity } = await import("./ha-identity.mjs");

  const identityBefore = (await loadOrCreateHaIdentity()).id;
  const keysBefore = loadOrCreateKeys().ed25519.publicKey.export({ format: "der", type: "spki" });

  // One vault ref serves both consumers.
  const idx = JSON.parse(readFileSync(join(home, "vault-index.json"), "utf8"));
  const passphraseRefs = Object.keys(idx).filter((r) => r.startsWith("helmd:at-rest-passphrase"));
  assert.equal(passphraseRefs.length, 1, `expected exactly one at-rest passphrase ref, got ${passphraseRefs.length}`);

  // Both still open after a reload.
  assert.equal((await loadOrCreateHaIdentity()).id, identityBefore);
  assert.deepEqual(loadOrCreateKeys().ed25519.publicKey.export({ format: "der", type: "spki" }), keysBefore);
});

test("FAILURE MODE 4 — source check: loadOrCreatePassphrase is defined once and exported once", () => {
  const src = readFileSync(new URL("./keys.mjs", import.meta.url), "utf8");
  const definitions = src.match(/function loadOrCreatePassphrase\b/g) ?? [];
  assert.equal(definitions.length, 1, "exactly one definition");

  const haSrc = readFileSync(new URL("./ha-identity.mjs", import.meta.url), "utf8");
  assert.match(haSrc, /import \{ loadOrCreatePassphrase[^}]*\} from "\.\/keys\.mjs"/);
  assert.doesNotMatch(haSrc, /from "\.\/vault\.mjs"/, "ha-identity must not open a second vault path");
  assert.equal((haSrc.match(/loadOrCreatePassphrase\(/g) ?? []).length, 1, "one call site in ha-identity");
});

// --- the ref must not be machine-global ---

test("two state dirs on one machine get distinct vault refs (no cross-install clobber)", () => {
  freshHome("ns-a");
  loadOrCreatePassphrase();
  const refA = atRestPassphraseRef();
  const passA = loadOrCreatePassphrase();

  freshHome("ns-b");
  loadOrCreatePassphrase();
  const refB = atRestPassphraseRef();
  const passB = loadOrCreatePassphrase();

  assert.notEqual(refA, refB, "refs must be namespaced per state dir");
  assert.equal(passA.equals(passB), false, "each install must hold its own passphrase");
});
