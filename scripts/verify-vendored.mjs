#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Re-verifies EVERY vendored tree's integrity + provenance:
//   - hub/vendored/ocg           (config-driven, single upstream: scripts/vendor.config.json)
//   - hub/vendored/anchor-suite  (config-driven, single upstream: scripts/vendor-anchor.config.json)
//   - ui/vendored                (heterogeneous, hand-ported: ui/vendored/MANIFEST.json)
// For each: local bytes must match the manifest's recorded hashes, and the
// manifest must carry non-empty `license` + `pinnedSha` for every tree/entry
// (HELM-VENDOR-LICENSE-1 — no vendored tree may ship without a license record;
// an Apache-2.0 project shipping unlicensed third-party bundles fails OSS/legal
// review before anyone looks at the crypto). The two config-driven trees ALSO
// get a live upstream re-fetch + byte comparison in the CLI path (HELM-SEC-3 /
// THREAT-MODEL §5 F3) — that part needs network, so it is kept OUT of the pure
// functions below (import.meta-guarded CLI only) so verify-vendored.test.mjs
// can exercise the local-only checks offline under `npm test`.
// Zero npm deps — git + node builtins only (STANDING ORDERS #10: never npm).
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

function sh(cmd, args, cwd) {
  // git invoking this script as a hook sets GIT_DIR/GIT_WORK_TREE in the
  // process env; child git processes inherit and honor those over cwd, so
  // the scratch clone below would otherwise silently target the CALLER's
  // repo instead of `tmp` (see HELM-TESTISO-1). Scrub them.
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  return execFileSync(cmd, args, { cwd, env, stdio: ["ignore", "pipe", "inherit"] }).toString();
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

export function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function nonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

// ---------------------------------------------------------------------------
// Config-driven trees: single upstream repo, single license — LOCAL checks
// only (manifest-vs-config metadata, license/pinnedSha presence, local bytes
// vs manifest hashes). No network.
// ---------------------------------------------------------------------------
export function collectConfigDrivenIssues(destRoot, config) {
  const issues = [];
  const manifestPath = join(destRoot, "MANIFEST.json");
  if (!existsSync(manifestPath)) {
    issues.push(`${config.destination}: no MANIFEST.json — every vendored tree must carry one (HELM-VENDOR-LICENSE-1).`);
    return issues;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));

  if (manifest.sourceRepo !== config.sourceRepo) {
    issues.push(`${config.destination}: MANIFEST sourceRepo drift: ${manifest.sourceRepo} != ${config.sourceRepo}`);
  }
  if (manifest.pinnedSha !== config.pinnedSha) {
    issues.push(`${config.destination}: MANIFEST pinnedSha drift: ${manifest.pinnedSha} != ${config.pinnedSha}`);
  }
  if (!nonEmptyString(manifest.pinnedSha)) {
    issues.push(`${config.destination}: MANIFEST missing/empty pinnedSha.`);
  }
  if (!nonEmptyString(manifest.license)) {
    issues.push(`${config.destination}: MANIFEST missing/empty license — every vendored tree must declare its license (HELM-VENDOR-LICENSE-1).`);
  }
  if (JSON.stringify(manifest.vendoredPaths) !== JSON.stringify(config.paths)) {
    issues.push(`${config.destination}: MANIFEST vendoredPaths drift`);
  }

  const onDisk = walk(destRoot)
    .map((f) => f.slice(destRoot.length + 1).replace(/\\/g, "/"))
    .filter((p) => p !== "MANIFEST.json")
    .sort();
  const inManifest = (manifest.files || []).map((f) => f.path).sort();

  if (JSON.stringify(onDisk) !== JSON.stringify(inManifest)) {
    const onDiskSet = new Set(onDisk);
    const manifestSet = new Set(inManifest);
    for (const p of onDisk) if (!manifestSet.has(p)) issues.push(`${config.destination}: file on disk but not in MANIFEST: ${p}`);
    for (const p of inManifest) if (!onDiskSet.has(p)) issues.push(`${config.destination}: file in MANIFEST but missing on disk: ${p}`);
  }

  for (const entry of manifest.files || []) {
    const abs = join(destRoot, entry.path);
    let actual;
    try {
      actual = sha256(abs);
    } catch {
      continue; // already reported as missing above
    }
    if (actual !== entry.sha256) {
      issues.push(`${config.destination}: hash mismatch: ${entry.path} (manifest ${entry.sha256} != on-disk ${actual})`);
    }
  }

  return issues;
}

// ---------------------------------------------------------------------------
// ui/vendored: heterogeneous tree — many upstreams, many licenses, hand-ported
// (no build step, no automated vendor script, so no live upstream refetch —
// there is no single remote to fetch). Checks local-bytes-vs-manifest and
// that every entry declares a non-empty sourceRepo/pinnedSha/license.
// ---------------------------------------------------------------------------
export function collectHeterogeneousIssues(destRoot, manifestPath, label) {
  const issues = [];
  if (!existsSync(manifestPath)) {
    issues.push(`${label}: no MANIFEST.json — every vendored tree must carry one (HELM-VENDOR-LICENSE-1).`);
    return issues;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    issues.push(`${label}: MANIFEST.json has no entries.`);
    return issues;
  }

  const manifestPaths = new Set();
  for (const [i, entry] of manifest.entries.entries()) {
    const where = `${label}/MANIFEST.json entries[${i}] (${entry.classification || "?"})`;
    if (!nonEmptyString(entry.classification)) issues.push(`${where}: missing classification`);
    if (!nonEmptyString(entry.sourceRepo)) issues.push(`${where}: missing/empty sourceRepo`);
    if (!nonEmptyString(entry.pinnedSha)) issues.push(`${where}: missing/empty pinnedSha`);
    if (!nonEmptyString(entry.license)) {
      issues.push(
        `${where}: missing/empty license — every vendored file must have a declared license (HELM-VENDOR-LICENSE-1); do not invent one, state why it can't be established instead.`
      );
    }
    if (!Array.isArray(entry.files) || entry.files.length === 0) {
      issues.push(`${where}: no files listed`);
      continue;
    }
    for (const f of entry.files) {
      if (!nonEmptyString(f.path) || !nonEmptyString(f.sha256)) {
        issues.push(`${where}: file entry missing path/sha256`);
        continue;
      }
      manifestPaths.add(f.path);
      const abs = join(destRoot, f.path);
      let actual;
      try {
        actual = sha256(abs);
      } catch {
        issues.push(`${label}: file in MANIFEST but missing on disk: ${f.path}`);
        continue;
      }
      if (actual !== f.sha256) {
        issues.push(`${label}: hash mismatch: ${f.path} (manifest ${f.sha256} != on-disk ${actual})`);
      }
    }
  }

  const onDisk = walk(destRoot)
    .map((f) => f.slice(destRoot.length + 1).replace(/\\/g, "/"))
    .filter((p) => p !== "MANIFEST.json")
    .sort();
  for (const p of onDisk) {
    if (!manifestPaths.has(p)) issues.push(`${label}: file on disk but not in MANIFEST: ${p}`);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Completeness: every known vendored root must be covered by one of the
// checks above — a NEW vendored tree added without a manifest must fail loud,
// not silently skip verification.
// ---------------------------------------------------------------------------
const KNOWN_VENDORED_ROOTS = new Set(["hub/vendored/ocg", "hub/vendored/anchor-suite", "ui/vendored"]);

export function collectUncoveredTreeIssues(root) {
  const issues = [];
  for (const base of ["hub/vendored", "ui/vendored"]) {
    const abs = join(root, base);
    if (!existsSync(abs)) continue;
    const isVendoredRootItself = base === "ui/vendored";
    const roots = isVendoredRootItself
      ? [base]
      : readdirSync(abs, { withFileTypes: true })
          .filter((e) => e.isDirectory())
          .map((e) => `${base}/${e.name}`);
    for (const r of roots) {
      if (!KNOWN_VENDORED_ROOTS.has(r)) {
        issues.push(`${r}: vendored tree is not covered by verify-vendored.mjs — add a manifest + wire it into this gate before landing (HELM-VENDOR-LICENSE-1).`);
      }
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Live upstream re-fetch + byte comparison (network) — a PR cannot tamper
// vendored files + regenerate MANIFEST to hide drift, because this compares
// against upstream git, a source this script never wrote to.
// ---------------------------------------------------------------------------
async function collectUpstreamDriftIssues(destRoot, config, mapRelPath) {
  const issues = [];
  const tmp = mkdtempSync(join(tmpdir(), "helm-verify-vendor-"));
  try {
    console.log(`Fetching ${config.sourceRepo} @ ${config.pinnedSha} for upstream comparison ...`);
    sh("git", ["init", "-q"], tmp);
    sh("git", ["remote", "add", "origin", config.sourceRepo], tmp);
    sh("git", ["fetch", "--depth", "1", "origin", config.pinnedSha], tmp);
    sh("git", ["checkout", "-q", "FETCH_HEAD"], tmp);

    for (const relPath of config.paths) {
      const src = join(tmp, relPath);
      const baseName = mapRelPath(relPath);
      const isDir = statSync(src).isDirectory();
      const files = isDir ? walk(src) : [src];
      for (const f of files) {
        const relFromBase = isDir ? join(baseName, f.slice(src.length + 1)) : baseName;
        const relKey = relFromBase.replace(/\\/g, "/");
        const vendoredPath = join(destRoot, relKey);
        let vendoredHash;
        try {
          vendoredHash = sha256(vendoredPath);
        } catch {
          issues.push(`${config.destination}: upstream file not vendored: ${relKey}`);
          continue;
        }
        const upstreamHash = sha256(f);
        if (vendoredHash !== upstreamHash) {
          issues.push(`${config.destination}: vendored bytes DRIFT from upstream: ${relKey}`);
        }
      }
    }
    if (issues.length === 0) {
      console.log(`${config.destination}: upstream comparison OK: vendored tree matches ${config.sourceRepo} @ ${config.pinnedSha}.`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  return issues;
}

async function runCLI() {
  let issues = [];

  const ocgConfig = JSON.parse(readFileSync(join(HERE, "vendor.config.json"), "utf8"));
  const anchorConfig = JSON.parse(readFileSync(join(HERE, "vendor-anchor.config.json"), "utf8"));

  const ocgIssues = collectConfigDrivenIssues(join(ROOT, ocgConfig.destination), ocgConfig);
  const anchorIssues = collectConfigDrivenIssues(join(ROOT, anchorConfig.destination), anchorConfig);
  issues = issues.concat(ocgIssues, anchorIssues);
  if (ocgIssues.length === 0) console.log(`${ocgConfig.destination}: local vendored tree OK.`);
  if (anchorIssues.length === 0) console.log(`${anchorConfig.destination}: local vendored tree OK.`);

  issues = issues.concat(collectHeterogeneousIssues(join(ROOT, "ui/vendored"), join(ROOT, "ui/vendored/MANIFEST.json"), "ui/vendored"));
  issues = issues.concat(collectUncoveredTreeIssues(ROOT));

  for (const msg of issues) console.error(msg);
  if (issues.length > 0) {
    console.error("Vendored-tree verification FAILED — see above.");
    process.exit(1);
  }

  // Live upstream comparison only once local checks are clean.
  // Each vendor script maps upstream paths to vendored-tree-relative paths
  // differently (scripts/vendor.mjs flattens to basename; scripts/vendor-anchor.mjs
  // strips the shared "public/" prefix and keeps the rest, so relative imports
  // between vendored files still resolve) — mirror each exactly, or a correct
  // upstream byte-for-byte match would misreport as "not vendored".
  const upstreamIssues = (
    await Promise.all([
      collectUpstreamDriftIssues(join(ROOT, ocgConfig.destination), ocgConfig, (relPath) => relPath.split("/").pop()),
      collectUpstreamDriftIssues(join(ROOT, anchorConfig.destination), anchorConfig, (relPath) => relPath.replace(/^public\//, "")),
    ])
  ).flat();

  if (upstreamIssues.length > 0) {
    for (const msg of upstreamIssues) console.error(msg);
    console.error("Vendored-tree verification FAILED — see above.");
    process.exit(1);
  }

  console.log("All vendored trees verified: manifests present, licensed, pinned, and byte-accurate.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runCLI();
}
