#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Builds the Node SEA (single executable application) binary for the
// CURRENT host platform (HELM-H8, D3/D10). Node SEA is not a cross-compiler
// — CI runs this once per OS in a build-matrix job, each producing its own
// native artifact into dist/<platform>-<arch>/. Injection uses the vendored,
// integrity-checked postject (scripts/vendor/postject/), not `npx postject@...`
// (HELM-POSTJECT-PIN-1) — npx only pins the VERSION, not the bytes the
// registry serves at build time, inside the exact pipeline whose provenance
// we attest; zero-dep discipline (D2) still holds because the vendored
// injector never enters package.json.
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, chmodSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, platform, arch } from "node:os";
import { fileURLToPath } from "node:url";
import { seaAssetMap } from "../hub/ui-manifest.mjs";
import { collectBackendSourceFiles, seaBackendAssetMap } from "../hub/sea-source-manifest.mjs";
import { injectSEA } from "./vendor/postject/inject.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
// The SEA main script must be CJS (see hub/sea-entry.cjs) — it dynamically
// imports the real (ESM) index.mjs from extracted, embedded source assets.
const ENTRY = join(ROOT, "hub", "sea-entry.cjs");
const SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
const VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;

function platformTag() {
  const p = platform() === "win32" ? "windows" : platform() === "darwin" ? "macos" : "linux";
  return `${p}-${arch()}`;
}

async function main() {
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
    const manifestPath = join(tmp, "src-manifest.json");
    const versionPath = join(tmp, "src-version.txt");
    writeFileSync(manifestPath, JSON.stringify(collectBackendSourceFiles()));
    writeFileSync(versionPath, VERSION);
    writeFileSync(
      configPath,
      JSON.stringify(
        {
          main: ENTRY,
          output: blobPath,
          disableExperimentalSEAWarning: true,
          assets: {
            ...seaAssetMap(),
            ...seaBackendAssetMap(),
            "src-manifest": manifestPath,
            "src-version": versionPath,
          },
        },
        null,
        2
      )
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

    const injectOptions = { sentinelFuse: SENTINEL_FUSE };
    if (platform() === "darwin") injectOptions.machoSegmentName = "NODE_SEA";
    await injectSEA(outPath, "NODE_SEA_BLOB", blobPath, injectOptions);

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

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
