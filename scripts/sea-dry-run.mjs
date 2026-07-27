#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// SEA build dry-run. Historically this only proved `--experimental-sea-config`
// produced a blob and stopped there ("injection needs postject at packaging
// time") — that gate is exactly why HELM-WIN-INSTALL-1 (helmd.exe crashing
// instantly with "Cannot use import statement outside a module" on every
// platform) shipped for a full release without CI ever noticing: proving the
// blob compiles proves nothing about whether the resulting binary can start.
// This now goes all the way: inject via the vendored, integrity-checked
// postject (scripts/vendor/postject/, same as build-sea.mjs — HELM-POSTJECT-PIN-1)
// and actually run the binary (`helmd doctor`), so a broken SEA main script
// fails CI instead of failing silently in a user's hands.
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync, existsSync, chmodSync, copyFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, platform } from "node:os";
import { fileURLToPath } from "node:url";
import { seaAssetMap } from "../hub/ui-manifest.mjs";
import { collectBackendSourceFiles, seaBackendAssetMap } from "../hub/sea-source-manifest.mjs";
import { injectSEA } from "./vendor/postject/inject.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ENTRY = join(ROOT, "hub", "sea-entry.cjs");
const SENTINEL_FUSE = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
const VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;

if (!existsSync(ENTRY)) {
  console.error(`sea-dry-run: missing entrypoint ${ENTRY}`);
  process.exit(1);
}

// postject@1.0.0-alpha.6 (the newest published version) reads the whole ~110MB
// node binary plus the asset-laden blob into JS memory. On Node >=24 that
// overruns V8's zone allocator and dies with "Fatal process out of memory:
// Zone" before injecting anything — and because it is a ZONE allocation,
// --max-old-space-size does not help. CI pins Node 22
// (.github/workflows/ci.yml), so this gate has always passed there and
// deterministically failed the pre-push hook on any Node 24 developer box.
//
// That made the gate CI-only in practice. This makes it CI-only BY DECISION,
// which is the difference between a known limitation and a mystery: skip on an
// unsupported local runtime, say why, and never skip in CI (where a skip would
// hide exactly the class of bug this gate exists to catch — see the header).
// Set HELM_FORCE_SEA=1 to run it anyway. Remove this branch when postject
// ships a fix or the toolchain moves to a Node that survives it.
const NODE_MAJOR = Number(process.versions.node.split(".")[0]);
if (NODE_MAJOR >= 24 && !process.env.CI && process.env.HELM_FORCE_SEA !== "1") {
  console.warn(
    `sea-dry-run: SKIPPED on Node ${process.versions.node} — postject@1.0.0-alpha.6 exhausts V8's ` +
      `zone allocator on Node >=24. CI runs this gate on Node 22 and is the authority. ` +
      `Force locally with HELM_FORCE_SEA=1.`
  );
  process.exit(0);
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
  await injectSEA(outPath, "NODE_SEA_BLOB", blobPath, { sentinelFuse: SENTINEL_FUSE });

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
  if (err && typeof err.message === "string" && err.message.startsWith("postject inject.mjs:")) {
    console.error(err.message);
    process.exit(1);
  }
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
