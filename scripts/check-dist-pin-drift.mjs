#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Nothing else compares a SHIPPED helmd binary's embedded kernel pins
// against the tree. sea-source-manifest.mjs only proves a fresh
// build extracts+runs (BUILD-TIME, sea-dry-run.mjs). release-manifest.mjs
// only hashes dist/ against itself. Both are internally consistent and
// neither compares the binary to the tree — a re-vendor can bump
// packs/*.json while a previously-built, previously-released dist/ binary
// keeps the old kernel_digest indefinitely, and every existing gate stays
// green (research/HELM-ART78-DELTA-SCOPE-1-2026-07-30.md).
//
// This runs the actual shipped binary for the HOST platform (`helmd
// doctor`, same trick sea-dry-run.mjs uses: sea-entry.cjs's extractRuntime()
// always runs before doctor's own checks, regardless of doctor's exit code)
// with HELM_HOME pointed at a scratch dir, then diffs the extracted
// packs/*.json kernel_digest pins against the tree's packs/*.json.
//
// Deliberately WARN, never FAIL: the binary is EXPECTED to lag the tree
// between a re-vendor landing and the next release rebuilding+shipping it —
// that gap is normal, not a regression, and hard-failing on it would red
// every helm CI run for days after a routine re-vendor. Deliberately SKIP
// (not pass, not fail) when dist/ or a host-matching platform binary is
// absent — most CI runs (helm's ci.yml) never build dist/ at all, so a
// silent pass there would look like proof of nothing.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir, platform, arch } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

export function platformTag() {
  const p = platform() === "win32" ? "windows" : platform() === "darwin" ? "macos" : "linux";
  return `${p}-${arch()}`;
}

export function distBinaryPath(distDir) {
  return join(distDir, platformTag(), platform() === "win32" ? "helmd.exe" : "helmd");
}

// { "<packFile>::<kernel_id>": "sha256:<hex>" } across every packs/*.json
// directly under `packsDir` — the same steps[].kernel_id/kernel_digest shape
// compile-packs.mjs writes and hub/kernel-runner.mjs reads.
export function collectPins(packsDir) {
  const pins = new Map();
  if (!existsSync(packsDir)) return pins;
  for (const f of readdirSync(packsDir)) {
    if (!f.endsWith(".json") || f === "INDEX.json") continue;
    let doc;
    try {
      doc = JSON.parse(readFileSync(join(packsDir, f), "utf8"));
    } catch {
      continue;
    }
    for (const node of doc.manifest?.nodes ?? []) {
      if (node.kernel_id && node.kernel_digest) pins.set(`${f}::${node.kernel_id}`, node.kernel_digest);
    }
  }
  return pins;
}

// Pins present in BOTH maps whose digest disagrees. A pin only the tree
// knows about (a brand-new kernel a stale binary predates) is not a
// mismatch — there is nothing stale to warn about, only something new.
export function diffPins(treePins, binPins) {
  const mismatches = [];
  for (const [key, treeDigest] of treePins) {
    const binDigest = binPins.get(key);
    if (binDigest && binDigest !== treeDigest) mismatches.push({ key, tree: treeDigest, binary: binDigest });
  }
  return mismatches;
}

function main() {
  const distDir = process.env.HELM_DIST_DIR || join(ROOT, "dist");
  const binPath = distBinaryPath(distDir);

  if (!existsSync(distDir) || !existsSync(binPath)) {
    console.log(
      `check-dist-pin-drift: SKIP — no ${platformTag()} binary at ${binPath} (dist/ absent, or this host's ` +
        `platform wasn't built/downloaded here). Not a pass and not a failure: there is nothing shipped to compare against.`
    );
    process.exit(0);
  }

  const treePins = collectPins(join(ROOT, "packs"));

  const tmp = mkdtempSync(join(tmpdir(), "helm-bingate-"));
  const home = join(tmp, "home");
  try {
    try {
      execFileSync(binPath, ["doctor"], { encoding: "utf8", env: { ...process.env, HELM_HOME: home } });
    } catch {
      // `doctor` legitimately exits non-zero on a failing local check (no
      // keychain in CI, etc — same rationale sea-dry-run.mjs documents).
      // extractRuntime() already ran, before doctor's own checks, either way.
    }

    const runtimeRoot = join(home, "_runtime");
    if (!existsSync(runtimeRoot)) {
      console.error(
        "check-dist-pin-drift: the binary ran but never extracted a _runtime/ cache — treating this as a " +
          "startup failure (the HELM-WIN-INSTALL-1 class of bug), not a skip."
      );
      process.exit(1);
    }
    const versions = readdirSync(runtimeRoot);
    if (versions.length !== 1) {
      console.error(`check-dist-pin-drift: expected exactly one extracted version under _runtime/, found [${versions.join(", ")}]`);
      process.exit(1);
    }

    const binPins = collectPins(join(runtimeRoot, versions[0], "packs"));
    const mismatches = diffPins(treePins, binPins);

    if (mismatches.length === 0) {
      console.log(
        `check-dist-pin-drift: OK — shipped ${platformTag()} binary (v${versions[0]}) pins match the tree ` +
          `(${treePins.size} kernel refs checked).`
      );
      process.exit(0);
    }

    console.warn(
      `check-dist-pin-drift: WARN — shipped ${platformTag()} binary (v${versions[0]}) embeds STALE kernel pins vs ` +
        `the current tree. Expected right after a re-vendor until the next release rebuilds+ships — not failing CI ` +
        `for it. Receipts/EUC cards already produced against the binary's pin stay valid; they will not reproduce ` +
        `against the tree until this binary is superseded.`
    );
    for (const m of mismatches) console.warn(`  ${m.key}: binary=${m.binary}  tree=${m.tree}`);
    process.exit(0);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
