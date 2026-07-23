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

test("file-fallback tier never writes the secret in plaintext to disk", () => {
  vaultSet("test:no-plaintext", { access_token: "SECRET-PLAINTEXT-CHECK" });
  if (vaultBackendFor("test:no-plaintext") !== "file-fallback") return; // only applies to this tier
  const dir = join(TMP, "vault");
  for (const f of readdirSync(dir)) {
    const contents = readFileSync(join(dir, f), "utf8");
    assert.doesNotMatch(contents, /SECRET-PLAINTEXT-CHECK/);
  }
});
