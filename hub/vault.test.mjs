import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-vault-test-"));
process.env.HELM_HOME = TMP;

const { vaultSet, vaultGet, vaultGetStrict, vaultDelete, vaultBackendFor } = await import("./vault.mjs");

after(() => rmSync(TMP, { recursive: true, force: true }));

test("round trip: set then get returns the same secret", () => {
  const secret = { access_token: "at-1", refresh_token: "rt-1", expires_at: 12345 };
  const { ref } = vaultSet("test:round-trip", secret);
  assert.deepEqual(vaultGet(ref), secret);
});

test("get on unknown ref returns null", () => {
  assert.equal(vaultGet("test:never-set"), null);
});

test("delete removes the secret", () => {
  vaultSet("test:to-delete", { access_token: "at-2" });
  vaultDelete("test:to-delete");
  assert.equal(vaultGet("test:to-delete"), null);
  assert.equal(vaultBackendFor("test:to-delete"), null);
});

test("vaultBackendFor reports the tier a ref landed on", () => {
  vaultSet("test:backend-check", { access_token: "at-3" });
  const backend = vaultBackendFor("test:backend-check");
  assert.ok(["macos-keychain", "windows-dpapi", "linux-secret-tool", "file-fallback"].includes(backend));
});

// KEYCHAIN-PROVABLE-1: the assertion above is the right shape for a
// connector-token-class secret (`access_token`) — worst case on a re-auth is
// the user signs in again, so tolerating file-fallback there is a genuine,
// named acceptance, not an oversight. The at-rest SIGNING-KEY passphrase
// (`passphrase_b64`, see keys.mjs) is a different class: file-fallback with no
// HELM_VAULT_PASSPHRASE override is exactly the pre-HELM-KEYCHAIN-1 exposure
// this vault exists to remove (key stored beside the ciphertext it
// protects), so a test that accepts it as a pass cannot detect the
// degradation. This is deliberately NOT a `t.skip` on the missing tiers: it
// judges whatever backend THIS run actually landed on.
test("signing-key-shaped secret (passphrase_b64) landing on file-fallback WITHOUT HELM_VAULT_PASSPHRASE is a failure, not a pass", () => {
  const priorEnv = process.env.HELM_VAULT_PASSPHRASE;
  delete process.env.HELM_VAULT_PASSPHRASE;
  const secret = { passphrase_b64: randomBytes(32).toString("base64") };
  let ref, backend;
  try {
    ({ ref, backend } = vaultSet("test:signing-key-tier-check", secret));
  } finally {
    if (priorEnv !== undefined) process.env.HELM_VAULT_PASSPHRASE = priorEnv;
  }
  vaultDelete(ref);
  assert.notEqual(
    backend,
    "file-fallback",
    "the at-rest signing-key passphrase must land on a native OS keychain tier in this environment; " +
      "file-fallback with no HELM_VAULT_PASSPHRASE means no reachable native keychain AND no opt-in " +
      "mitigation — a real gap here, not a test bug. See KEYCHAIN-PROVABLE-1 / hub/keys.mjs provisionPassphrase."
  );
});

// --- native-tier round trips, mirroring the windows-dpapi tests below: must
// genuinely exercise the tier when it is reachable, and skip LOUDLY (via
// t.skip, visible in the test-runner summary) rather than silently
// (a bare `return`, indistinguishable from an empty pass) when it is not. ---

test("linux-secret-tool: round trip works when the tier is genuinely available", (t) => {
  if (process.platform !== "linux") {
    t.skip("tier only reachable on linux");
    return;
  }
  const secret = { access_token: "LINUX-SECRET-TOOL-CHECK" };
  const { ref, backend } = vaultSet("test:secret-tool-live", secret);
  if (backend !== "linux-secret-tool") {
    t.skip(`Secret Service not reachable in this environment — vaultSet fell back to "${backend}" instead of ` +
      `linux-secret-tool. Install libsecret + run a Secret Service daemon (secret-tool, gnome-keyring, or ` +
      `equivalent) to exercise this tier.`);
    vaultDelete(ref);
    return;
  }
  assert.deepEqual(vaultGet(ref), secret);
  vaultDelete(ref);
});

test("macos-keychain: round trip works when the tier is genuinely available", (t) => {
  if (process.platform !== "darwin") {
    t.skip("tier only reachable on darwin");
    return;
  }
  const secret = { access_token: "MACOS-KEYCHAIN-CHECK" };
  const { ref, backend } = vaultSet("test:macos-keychain-live", secret);
  if (backend !== "macos-keychain") {
    t.skip(`macOS Keychain not reachable in this environment — vaultSet fell back to "${backend}" instead of ` +
      `macos-keychain.`);
    vaultDelete(ref);
    return;
  }
  assert.deepEqual(vaultGet(ref), secret);
  vaultDelete(ref);
});

test("windows-dpapi: round trip still works with secret passed via stdin", () => {
  if (process.platform !== "win32") return; // tier only reachable on win32
  const secret = { access_token: "DPAPI-STDIN-CHECK-SECRET" };
  const { ref, backend } = vaultSet("test:dpapi-stdin", secret);
  assert.equal(backend, "windows-dpapi");
  assert.deepEqual(vaultGet(ref), secret);
  vaultDelete(ref);
});

test("windows-dpapi: secret/ciphertext reach powershell.exe only via stdin, never argv (HELM-SEC-2, F2)", async () => {
  const src = await import("node:fs").then((fs) => fs.readFileSync(new URL("./vault.mjs", import.meta.url), "utf8"));
  const windowsSetBody = src.slice(src.indexOf("function windowsSet"), src.indexOf("function windowsGet"));
  const windowsGetBody = src.slice(src.indexOf("function windowsGet"), src.indexOf("function windowsDelete"));
  for (const body of [windowsSetBody, windowsGetBody]) {
    assert.match(body, /spawnSync\("powershell\.exe",\s*\[[^\]]*\],\s*\{\s*input:/s, "secret must be passed via the input: option");
    assert.doesNotMatch(body, /FromBase64String\('\$\{/, "no direct string-interpolation of secret bytes into the -Command script");
  }
});

test("HELM_VAULT_PASSPHRASE (HELM-SEC-5, F5): round trip works when set", () => {
  process.env.HELM_VAULT_PASSPHRASE = "correct horse battery staple";
  try {
    const secret = { access_token: "PASSPHRASE-DERIVED-KEY-CHECK" };
    const { ref } = vaultSet("test:passphrase", secret);
    assert.deepEqual(vaultGet(ref), secret);
    vaultDelete(ref);
  } finally {
    delete process.env.HELM_VAULT_PASSPHRASE;
  }
});

test("HELM_VAULT_PASSPHRASE (HELM-SEC-5, F5): a value encrypted under one passphrase does not decrypt under another", () => {
  process.env.HELM_VAULT_PASSPHRASE = "passphrase-one";
  const { ref } = vaultSet("test:passphrase-mismatch", { access_token: "SHOULD-NOT-DECRYPT" });
  if (vaultBackendFor(ref) !== "file-fallback") {
    delete process.env.HELM_VAULT_PASSPHRASE;
    return; // only meaningful for the file-fallback tier
  }
  process.env.HELM_VAULT_PASSPHRASE = "passphrase-two";
  try {
    assert.throws(() => vaultGet(ref));
  } finally {
    delete process.env.HELM_VAULT_PASSPHRASE;
  }
});

// --- vaultGetStrict (HELM-KEYCHAIN-1) ---

test("vaultGetStrict: returns null for a ref that was never stored", () => {
  assert.equal(vaultGetStrict("test:strict-never-set"), null);
});

test("vaultGetStrict: round-trips a stored secret like vaultGet", () => {
  const secret = { passphrase_b64: "c3RyaWN0LXJvdW5kLXRyaXA=" };
  const { ref } = vaultSet("test:strict-round-trip", secret);
  assert.deepEqual(vaultGetStrict(ref), secret);
  vaultDelete(ref);
});

test("vaultGetStrict: an indexed ref whose tier lost the value THROWS instead of returning null", () => {
  const ref = "test:strict-destroyed";
  vaultSet(ref, { passphrase_b64: "d2lsbC1iZS1kZXN0cm95ZWQ=" });
  const tier = vaultBackendFor(ref);

  // Destroy the value but leave the index entry — an OS keychain reset, a
  // locked keyring, a moved profile. vaultGet's cross-tier fallback would
  // report null here; vaultGetStrict must refuse.
  vaultDelete(ref);
  const idxPath = join(TMP, "vault-index.json");
  const idx = JSON.parse(readFileSync(idxPath, "utf8"));
  writeFileSync(idxPath, JSON.stringify({ ...idx, [ref]: tier }, null, 2) + "\n", { mode: 0o600 });

  assert.equal(vaultGet(ref), null, "vaultGet stays forgiving for connector tokens");
  assert.throws(() => vaultGetStrict(ref), /no longer holds it/);

  delete idx[ref];
  writeFileSync(idxPath, JSON.stringify(idx, null, 2) + "\n", { mode: 0o600 });
});

test("file-fallback tier never writes the secret in plaintext to disk", () => {
  vaultSet("test:no-plaintext", { access_token: "SECRET-PLAINTEXT-CHECK" });
  if (vaultBackendFor("test:no-plaintext") !== "file-fallback") return; // only applies to this tier
  const dir = join(TMP, "vault");
  for (const f of readdirSync(dir)) {
    const contents = readFileSync(join(dir, f), "utf8");
    assert.doesNotMatch(contents, /SECRET-PLAINTEXT-CHECK/);
  }
});
