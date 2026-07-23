#!/usr/bin/env node
// Vendors pinned OCG kernels + verify libs from PostOakLabs/ainumbers into hub/vendored/ocg.
// Single-writer: run this script alone, commit the pinned SHA in the commit message.
// Zero npm deps — git + node builtins only (STANDING ORDERS #10: never npm).
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  rmSync,
  mkdirSync,
  cpSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const config = JSON.parse(readFileSync(join(HERE, "vendor.config.json"), "utf8"));

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

const tmp = mkdtempSync(join(tmpdir(), "helm-vendor-"));
try {
  console.log(`Cloning ${config.sourceRepo} @ ${config.pinnedSha} ...`);
  sh("git", ["init", "-q"], tmp);
  sh("git", ["remote", "add", "origin", config.sourceRepo], tmp);
  sh("git", ["fetch", "--depth", "1", "origin", config.pinnedSha], tmp);
  sh("git", ["checkout", "-q", "FETCH_HEAD"], tmp);

  const destRoot = join(ROOT, config.destination);
  rmSync(destRoot, { recursive: true, force: true });
  mkdirSync(destRoot, { recursive: true });

  const manifestEntries = [];
  for (const relPath of config.paths) {
    const src = join(tmp, relPath);
    const baseName = relPath.split("/").pop();
    const dest = join(destRoot, baseName);
    cpSync(src, dest, { recursive: true });
    const files = statSync(src).isDirectory() ? walk(dest) : [dest];
    for (const f of files) {
      manifestEntries.push({
        path: f.slice(destRoot.length + 1).replace(/\\/g, "/"),
        sha256: sha256(f),
      });
    }
  }

  manifestEntries.sort((a, b) => a.path.localeCompare(b.path));
  writeFileSync(
    join(destRoot, "MANIFEST.json"),
    JSON.stringify(
      {
        sourceRepo: config.sourceRepo,
        pinnedSha: config.pinnedSha,
        vendoredPaths: config.paths,
        fileCount: manifestEntries.length,
        files: manifestEntries,
      },
      null,
      2
    ) + "\n"
  );

  console.log(`Vendored ${manifestEntries.length} files into ${config.destination} @ ${config.pinnedSha}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
