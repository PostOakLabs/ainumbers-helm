#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// SEA build dry-run. Historically this only proved `--experimental-sea-config`
// produced a blob and stopped there ("injection needs postject at packaging
// time") — that gate is exactly why HELM-WIN-INSTALL-1 (helmd.exe crashing
// instantly with "Cannot use import statement outside a module" on every
// platform) shipped for a full release without CI ever noticing: proving the
// blob compiles proves nothing about whether the resulting binary can start.
// This now goes all the way: inject via postject (same as build-sea.mjs) and
// actually run the binary (`helmd doctor`), so a broken SEA main script fails
// CI instead of failing silently in a user's hands.
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync, existsSync, chmodSync, copyFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, platform } from "node:os";
import { fileURLToPath } from "node:url";
import { seaAssetMap } from "../hub/ui-manifest.mjs";
import { collectBackendSourceFiles, seaBackendAssetMap } from "../hub/sea-source-manifest.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(ROOT, "hub", "sea-entry.cjs");
const SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
const VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;

if (!existsSync(ENTRY)) {
  console.error(`sea-dry-run: missing entrypoint ${ENTRY}`);
  process.exit(1);
}

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
  if (!existsSync(blobPath)) {
    console.error("sea-dry-run: blob was not produced");
    process.exit(1);
  }
  console.log("sea-dry-run: blob generated — injecting + smoke-running the actual binary");

  const isWin = platform() === "win32";
  const outPath = join(tmp, isWin ? "helmd.exe" : "helmd");
  copyFileSync(process.execPath, outPath);
  chmodSync(outPath, 0o755);
  execFileSync(
    "npx",
    ["--yes", "postject@1.0.0-alpha.6", outPath, "NODE_SEA_BLOB", blobPath, "--sentinel-fuse", SENTINEL_FUSE],
    { stdio: "inherit", shell: isWin }
  );

  const homeDir = join(tmp, "sea-dry-run-home");
  const result = execFileSync(outPath, ["doctor"], {
    encoding: "utf8",
    env: { ...process.env, HELM_HOME: homeDir },
    // `doctor` exits non-zero on a failing check (e.g. no keychain in CI) —
    // that's a legitimate doctor finding, not a smoke-test failure. What
    // this gate exists to catch is the binary failing to START at all
    // (the ESM-in-SEA crash), which throws before any doctor output exists.
  }).toString();
  if (!result.includes("PASS") && !result.includes("FAIL")) {
    console.error("sea-dry-run: binary ran but produced no recognizable doctor output:\n" + result);
    process.exit(1);
  }
  console.log("sea-dry-run: OK — binary starts and runs `helmd doctor`");
  console.log(result);
} catch (err) {
  // execFileSync throws even on a non-zero doctor exit; that's fine (see
  // above) as long as it actually produced doctor output on stdout.
  const out = err && err.stdout ? err.stdout.toString() : "";
  if (out.includes("PASS") || out.includes("FAIL")) {
    console.log("sea-dry-run: OK — binary starts and runs `helmd doctor` (non-zero exit from a doctor check, not a startup failure)");
    console.log(out);
  } else {
    console.error("sea-dry-run: binary failed to start");
    console.error(err && err.stack ? err.stack : err);
    process.exit(1);
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
