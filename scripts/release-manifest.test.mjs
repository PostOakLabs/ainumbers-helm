import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeys, serializeKeys } from "../hub/keys.mjs";
import { verifyReleaseManifest } from "./verify-release-manifest.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const TMP = mkdtempSync(join(tmpdir(), "helm-release-manifest-test-"));
const distDir = join(TMP, "dist");
mkdirSync(join(distDir, "linux-x64"), { recursive: true });
writeFileSync(join(distDir, "linux-x64", "helmd"), "fake sea binary bytes");

const testKeys = generateKeys();
const secretB64 = Buffer.from(JSON.stringify(serializeKeys(testKeys))).toString("base64");
const pkgVersion = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;

test("release-manifest: build script signs dist/, verify-release-manifest confirms it", () => {
  execFileSync(process.execPath, [join(ROOT, "scripts", "release-manifest.mjs")], {
    env: { ...process.env, HELM_RELEASE_SIGNING_KEY_B64: secretB64, HELM_RELEASE_VERSION: pkgVersion, HELM_RELEASE_DIST_DIR: distDir },
    stdio: "pipe",
  });

  assert.ok(existsSync(join(distDir, "release-manifest.json")));
  assert.ok(existsSync(join(distDir, "release-manifest.dsse.json")));

  const statement = JSON.parse(readFileSync(join(distDir, "release-manifest.json"), "utf8"));
  assert.equal(statement.predicate.version, pkgVersion);
  assert.equal(statement.subject.length, 1);
});

test("release-manifest: tag version mismatching package.json refuses to sign", () => {
  assert.throws(() => {
    execFileSync(process.execPath, [join(ROOT, "scripts", "release-manifest.mjs")], {
      env: { ...process.env, HELM_RELEASE_SIGNING_KEY_B64: secretB64, HELM_RELEASE_VERSION: "9.9.9-mismatch", HELM_RELEASE_DIST_DIR: distDir },
      stdio: "pipe",
    });
  }, /Command failed/);
});

test("verify-release-manifest: tampered artifact bytes fail digest check", () => {
  writeFileSync(join(distDir, "linux-x64", "helmd"), "TAMPERED");
  const result = verifyReleaseManifest(distDir, { ed25519: testKeys.ed25519.publicKey, mldsa44: testKeys.mldsa44.publicKey });
  assert.equal(result.ok, false);
  assert.equal(result.reason, "artifact digest mismatch");
  rmSync(TMP, { recursive: true, force: true });
});
