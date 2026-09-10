#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Vendors the pinned worker `otelspan.mjs` (plus the two shared-kernel modules
// it imports) from PostOakLabs/ainumbers-mcp-apps into
// hub/vendored/worker-otelspan. Byte-style sibling of scripts/vendor-anchor.mjs
// (HELM-OTEL-1): scripts/vendor.mjs can't carry this file because its config
// is a single-upstream pin on the SITE repository (PostOakLabs/ainumbers) and
// its run wipes `hub/vendored/ocg` wholesale — otelspan.mjs lives in a
// DIFFERENT upstream (the worker repo), so it gets its own pin, its own tree,
// and its own writer. The tree keeps the source's relative directory shape
// (otelspan.mjs at the root importing ./kernels/_hash.mjs and
// ./kernels/_proof.mjs) so the vendored imports resolve unchanged.
// Single-writer: run this script alone, commit the pinned SHA in the commit
// message. Zero npm deps — git + node builtins only (STANDING ORDERS #10).
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, cpSync, writeFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const config = JSON.parse(readFileSync(join(HERE, "vendor-worker.config.json"), "utf8"));

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

const tmp = mkdtempSync(join(tmpdir(), "helm-vendor-worker-"));
try {
  console.log(`Cloning ${config.sourceRepo} @ ${config.pinnedSha} ...`);
  sh("git", ["init", "-q"], tmp);
  sh("git", ["config", "core.autocrlf", "false"], tmp);
  sh("git", ["remote", "add", "origin", config.sourceRepo], tmp);
  sh("git", ["fetch", "--depth", "1", "origin", config.pinnedSha], tmp);
  sh("git", ["checkout", "-q", "FETCH_HEAD"], tmp);

  const destRoot = join(ROOT, config.destination);
  rmSync(destRoot, { recursive: true, force: true });
  mkdirSync(destRoot, { recursive: true });

  // Identity path mapping: preserve the source's relative directory shape
  // exactly (no basename flattening) so vendored relative imports resolve.
  const manifestEntries = [];
  for (const relPath of config.paths) {
    const src = join(tmp, relPath);
    const dest = join(destRoot, relPath);
    mkdirSync(dirname(dest), { recursive: true });
    cpSync(src, dest, { recursive: true });
    const files = statSync(src).isDirectory() ? walk(dest) : [dest];
    for (const f of files) {
      manifestEntries.push({ path: relative(destRoot, f).replace(/\\/g, "/"), sha256: sha256(f) });
    }
  }

  manifestEntries.sort((a, b) => a.path.localeCompare(b.path));
  writeFileSync(
    join(destRoot, "MANIFEST.json"),
    JSON.stringify(
      { sourceRepo: config.sourceRepo, license: config.license, pinnedSha: config.pinnedSha, vendoredPaths: config.paths, fileCount: manifestEntries.length, files: manifestEntries },
      null,
      2
    ) + "\n"
  );

  console.log(`Vendored ${manifestEntries.length} files into ${config.destination} @ ${config.pinnedSha}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
