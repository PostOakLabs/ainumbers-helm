#!/usr/bin/env node
// Re-verifies hub/vendored/ocg/ integrity: local bytes vs MANIFEST.json hashes,
// and MANIFEST bytes vs upstream pinnedSha (HELM-SEC-3 / THREAT-MODEL §5 F3).
// Zero npm deps — git + node builtins only (STANDING ORDERS #10: never npm).
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const config = JSON.parse(readFileSync(join(HERE, "vendor.config.json"), "utf8"));
const destRoot = join(ROOT, config.destination);
const manifest = JSON.parse(readFileSync(join(destRoot, "MANIFEST.json"), "utf8"));

function sh(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, stdio: ["ignore", "pipe", "inherit"] }).toString();
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

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

let failed = false;

// 1. MANIFEST metadata must match vendor.config.json (no silent re-point/re-path).
if (manifest.sourceRepo !== config.sourceRepo) {
  console.error(`MANIFEST sourceRepo drift: ${manifest.sourceRepo} != ${config.sourceRepo}`);
  failed = true;
}
if (manifest.pinnedSha !== config.pinnedSha) {
  console.error(`MANIFEST pinnedSha drift: ${manifest.pinnedSha} != ${config.pinnedSha}`);
  failed = true;
}
if (JSON.stringify(manifest.vendoredPaths) !== JSON.stringify(config.paths)) {
  console.error(`MANIFEST vendoredPaths drift`);
  failed = true;
}

// 2. Local vendored bytes must match the hashes recorded in MANIFEST — no file added,
//    removed, or edited since vendor.mjs last ran.
const onDisk = walk(destRoot)
  .map((f) => f.slice(destRoot.length + 1).replace(/\\/g, "/"))
  .filter((p) => p !== "MANIFEST.json")
  .sort();
const inManifest = manifest.files.map((f) => f.path).sort();

if (JSON.stringify(onDisk) !== JSON.stringify(inManifest)) {
  const onDiskSet = new Set(onDisk);
  const manifestSet = new Set(inManifest);
  for (const p of onDisk) if (!manifestSet.has(p)) console.error(`file on disk but not in MANIFEST: ${p}`);
  for (const p of inManifest) if (!onDiskSet.has(p)) console.error(`file in MANIFEST but missing on disk: ${p}`);
  failed = true;
}

for (const entry of manifest.files) {
  const abs = join(destRoot, entry.path);
  let actual;
  try {
    actual = sha256(abs);
  } catch {
    continue; // already reported as missing above
  }
  if (actual !== entry.sha256) {
    console.error(`hash mismatch: ${entry.path} (manifest ${entry.sha256} != on-disk ${actual})`);
    failed = true;
  }
}

if (failed) {
  console.error("Local vendored-tree verification FAILED — see above.");
  process.exit(1);
}
console.log(`Local vendored tree OK: ${manifest.files.length} files match MANIFEST.json.`);

// 3. Re-fetch pinnedSha from the upstream site repo and confirm vendored bytes match
//    upstream byte-for-byte — a PR cannot tamper vendored files + regenerate MANIFEST
//    to hide drift, because this compares against a source MANIFEST never wrote to.
const tmp = mkdtempSync(join(tmpdir(), "helm-verify-vendor-"));
try {
  console.log(`Fetching ${config.sourceRepo} @ ${config.pinnedSha} for upstream comparison ...`);
  sh("git", ["init", "-q"], tmp);
  sh("git", ["remote", "add", "origin", config.sourceRepo], tmp);
  sh("git", ["fetch", "--depth", "1", "origin", config.pinnedSha], tmp);
  sh("git", ["checkout", "-q", "FETCH_HEAD"], tmp);

  let upstreamFailed = false;
  for (const relPath of config.paths) {
    const src = join(tmp, relPath);
    const baseName = relPath.split("/").pop();
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
        console.error(`upstream file not vendored: ${relKey}`);
        upstreamFailed = true;
        continue;
      }
      const upstreamHash = sha256(f);
      if (vendoredHash !== upstreamHash) {
        console.error(`vendored bytes DRIFT from upstream: ${relKey}`);
        upstreamFailed = true;
      }
    }
  }

  if (upstreamFailed) {
    console.error("Upstream drift verification FAILED — vendored tree does not match pinnedSha bytes.");
    process.exit(1);
  }
  console.log(`Upstream comparison OK: vendored tree matches ${config.sourceRepo} @ ${config.pinnedSha}.`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
