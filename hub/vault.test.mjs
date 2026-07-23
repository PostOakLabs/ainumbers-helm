import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-vault-test-"));
process.env.HELM_HOME = TMP;

const { vaultSet, vaultGet, vaultDelete, vaultBackendFor } = await import("./vault.mjs");

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

test("file-fallback tier never writes the secret in plaintext to disk", () => {
  vaultSet("test:no-plaintext", { access_token: "SECRET-PLAINTEXT-CHECK" });
  if (vaultBackendFor("test:no-plaintext") !== "file-fallback") return; // only applies to this tier
  const dir = join(TMP, "vault");
  for (const f of readdirSync(dir)) {
    const contents = readFileSync(join(dir, f), "utf8");
    assert.doesNotMatch(contents, /SECRET-PLAINTEXT-CHECK/);
  }
});
