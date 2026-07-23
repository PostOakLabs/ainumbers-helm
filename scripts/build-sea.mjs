#!/usr/bin/env node
// Builds the Node SEA (single executable application) binary for the
// CURRENT host platform (HELM-H8, D3/D10). Node SEA is not a cross-compiler
// — CI runs this once per OS in a build-matrix job, each producing its own
// native artifact into dist/<platform>-<arch>/. Injection uses `postject`
// via npx (an ephemeral CI tool invocation, not a package.json dependency —
// zero-dep discipline per D2 covers the shipped product, not one-shot build
// tooling).
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, platform, arch } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(ROOT, "hub", "index.mjs");
const SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

function platformTag() {
  const p = platform() === "win32" ? "windows" : platform() === "darwin" ? "macos" : "linux";
  return `${p}-${arch()}`;
}

function main() {
  if (!existsSync(ENTRY)) {
    console.error(`build-sea: missing entrypoint ${ENTRY}`);
    process.exit(1);
  }

  const tag = platformTag();
  const outDir = join(ROOT, "dist", tag);
  mkdirSync(outDir, { recursive: true });
  const isWin = platform() === "win32";
  const outPath = join(outDir, isWin ? "helmd.exe" : "helmd");

  const tmp = mkdtempSync(join(tmpdir(), "helm-sea-"));
  try {
    const configPath = join(tmp, "sea-config.json");
    const blobPath = join(tmp, "helmd.blob");
    writeFileSync(
      configPath,
      JSON.stringify({ main: ENTRY, output: blobPath, disableExperimentalSEAWarning: true }, null, 2)
    );
    execFileSync(process.execPath, ["--experimental-sea-config", configPath], { stdio: "inherit" });

    copyFileSync(process.execPath, outPath);
    chmodSync(outPath, 0o755);

    if (platform() === "darwin") {
      try {
        execFileSync("codesign", ["--remove-signature", outPath], { stdio: "inherit" });
      } catch {
        console.warn("build-sea: codesign --remove-signature failed/unavailable — continuing (dev host)");
      }
    }

    const postjectArgs = [
      // postject publishes prerelease versions only — "@1" matches nothing (ETARGET); pin exact
      "--yes", "postject@1.0.0-alpha.6", outPath, "NODE_SEA_BLOB", blobPath,
      "--sentinel-fuse", SENTINEL_FUSE,
    ];
    if (platform() === "darwin") postjectArgs.push("--macho-segment-name", "NODE_SEA");
    execFileSync("npx", postjectArgs, { stdio: "inherit", shell: isWin });

    if (platform() === "darwin") {
      try {
        execFileSync("codesign", ["--sign", "-", outPath], { stdio: "inherit" });
      } catch {
        console.warn("build-sea: ad-hoc codesign failed/unavailable — binary may not run unmodified on macOS");
      }
    }

    console.log(`build-sea: OK -> ${outPath}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

main();
