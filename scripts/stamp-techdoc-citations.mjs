#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// stamp-techdoc-citations.mjs — HUMAN-INVOKED re-stamp for the technical
// design doc's citation manifest. Run this only after re-reading the claims in
// docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md that cite the changed files and
// correcting the prose where the code moved.
//
// ⛔⛔ NEVER WIRE THIS INTO CI OR A GIT HOOK. The stamp is an assertion that a
// human re-verified the doc against the code. A manifest that regenerates
// itself makes scripts/check-techdoc-citations.mjs pass unconditionally, which
// is worse than deleting that gate outright: it advertises a guarantee it no
// longer provides. The PR that re-stamps must be the PR that re-verified.
//
// Zero npm deps — git + node builtins only (STANDING ORDERS #10: never npm).
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { extractCitations, citationDigest, ROOT, DOC_REL, MANIFEST_REL } from "./check-techdoc-citations.mjs";

function headSha() {
  try {
    // Scrub git's hook env so this targets THIS repo, not a caller's
    // (same hazard verify-vendored.mjs documents).
    const env = { ...process.env };
    delete env.GIT_DIR;
    delete env.GIT_WORK_TREE;
    delete env.GIT_INDEX_FILE;
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, env, stdio: ["ignore", "pipe", "inherit"] }).toString().trim();
  } catch {
    return null;
  }
}

function main() {
  const docText = readFileSync(join(ROOT, DOC_REL), "utf8");
  const cites = extractCitations(docText);

  const files = [];
  const missing = [];
  for (const path of [...cites.keys()].sort()) {
    const abs = join(ROOT, path);
    if (!existsSync(abs)) {
      missing.push(path);
      continue;
    }
    files.push({ path, sha256: citationDigest(path, abs) });
  }

  if (missing.length) {
    console.error(`✗ stamp refused: the doc cites ${missing.length} file(s) that do not exist:`);
    for (const p of missing) console.error(`    - ${p}`);
    console.error("  Fix the citation in the doc first. Stamping around a dangling citation would");
    console.error("  record that a nonexistent file was verified.");
    process.exit(1);
  }

  const manifest = {
    _comment:
      "Anti-drift stamp for HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md. Each entry is a file the doc cites, digested as of the last time a human re-read the doc's claims against that code. Enforced by scripts/check-techdoc-citations.mjs. Re-stamp with scripts/stamp-techdoc-citations.mjs, by hand, in the same pull request that re-verifies the prose. Never automatically.",
    doc: DOC_REL,
    stampedAtSha: headSha(),
    files,
  };

  writeFileSync(join(ROOT, MANIFEST_REL), JSON.stringify(manifest, null, 2) + "\n");
  console.log(`✓ stamped ${files.length} cited file(s) into ${MANIFEST_REL} at ${manifest.stampedAtSha || "(no git sha available)"}.`);
  console.log("  Commit this in the same PR as the doc corrections it certifies.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
