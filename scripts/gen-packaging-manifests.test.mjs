import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const TMP = mkdtempSync(join(tmpdir(), "helm-gen-packaging-test-"));
const distDir = join(TMP, "dist");
mkdirSync(distDir, { recursive: true });

writeFileSync(
  join(distDir, "release-manifest.json"),
  JSON.stringify({
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      { name: "windows-x64/helmd.exe", digest: { sha256: "1".repeat(64) }, size: 1 },
      { name: "macos-arm64/helmd", digest: { sha256: "2".repeat(64) }, size: 1 },
      { name: "macos-x64/helmd", digest: { sha256: "3".repeat(64) }, size: 1 },
      { name: "linux-x64/helmd", digest: { sha256: "4".repeat(64) }, size: 1 },
    ],
    predicateType: "https://ainumbers.co/helm/attestation/v1#release-manifest",
    predicate: { version: "9.9.9-test", node_version: process.version, platforms: ["windows-x64", "macos-arm64", "macos-x64", "linux-x64"] },
  })
);

test("gen-packaging-manifests: fills every template with the release manifest's version + digests", () => {
  execFileSync(process.execPath, [join(ROOT, "scripts", "gen-packaging-manifests.mjs")], {
    env: { ...process.env, HELM_RELEASE_DIST_DIR: distDir },
    stdio: "pipe",
  });

  const winget = readFileSync(join(distDir, "packaging", "winget", "AINumbers.Helm.installer.yaml"), "utf8");
  assert.match(winget, /PackageVersion: 9\.9\.9-test/);
  assert.match(winget, new RegExp("1".repeat(64)));

  const brew = readFileSync(join(distDir, "packaging", "homebrew", "helm.rb"), "utf8");
  assert.match(brew, /version "9\.9\.9-test"/);
  assert.match(brew, new RegExp("2".repeat(64)));
  assert.match(brew, new RegExp("3".repeat(64)));

  const npmInstall = readFileSync(join(distDir, "packaging", "npm", "bin", "install.mjs"), "utf8");
  assert.match(npmInstall, new RegExp("4".repeat(64)));
  assert.doesNotMatch(npmInstall, /\{\{/);

  rmSync(TMP, { recursive: true, force: true });
});
