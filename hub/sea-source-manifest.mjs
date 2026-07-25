// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Node's SEA main script is loaded as CommonJS — an ESM entrypoint (what
// index.mjs is, and what the whole hub/ module graph is written in) fails
// instantly with "Cannot use import statement outside a module". There is no
// SEA-supported way to run an ESM main directly, and this project is
// zero-dep (D2) so no bundler is available to flatten hub/ into one CJS
// file. The fix: embed every file the daemon can load or read as a SEA
// asset (same mechanism ui-manifest.mjs already uses for the UI), extract
// them to a per-version cache dir at runtime (sea-entry.cjs) mirroring the
// real repo layout, and dynamically `import()` the real index.mjs from
// there — the SEA main script itself stays a tiny CJS shim that never uses
// `import`.
//
// A precise static import-graph walk (following only `import`/`export
// ... from` and dynamic `import(literal)`) is NOT enough: several hub/*.mjs
// modules also `readFileSync` plain data files at runtime — schema JSON
// (hub/*.mjs -> ../schema/*.schema.json), pack definitions (packs/*.json),
// and vendored kernel manifests/fixtures (hub/vendored/ocg/**) — none of
// which show up in an import graph. Rather than hand-maintain a second list
// of every data file (guaranteed to drift), this embeds whole directories
// known to hold runtime inputs: hub/, ui/, schema/, packs/, scripts/lib/,
// plus the root package.json (doctor.mjs / server.mjs read it for the
// daemon version). Test files (*.test.mjs) are the only exclusion — they
// are dev-only and never imported by index.mjs's graph.
import { readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..");

// Repo-root-relative dirs whose full contents the daemon may load or read
// at runtime, plus individual files needed the same way.
const RUNTIME_DIRS = ["hub", "ui", "schema", "packs", "scripts/lib"];
const RUNTIME_FILES = ["package.json"];

function walk(dir, out) {
  for (const name of readdirSync(dir).sort()) {
    const abs = join(dir, name);
    const st = statSync(abs);
    if (st.isDirectory()) {
      walk(abs, out);
    } else if (!name.endsWith(".test.mjs")) {
      out.push(abs);
    }
  }
}

// Sorted, repo-root-relative, POSIX-style paths (e.g. "hub/server.mjs",
// "schema/envelope.schema.json") for every runtime-relevant file.
export function collectBackendSourceFiles() {
  const abs = [];
  for (const rel of RUNTIME_DIRS) walk(join(REPO_ROOT, ...rel.split("/")), abs);
  for (const rel of RUNTIME_FILES) abs.push(join(REPO_ROOT, rel));
  return abs.map((f) => relative(REPO_ROOT, f).split("\\").join("/")).sort();
}

// Flat { "src/<rel>": "<abs path>" } map for sea-config's `assets` field,
// mirroring seaAssetMap()'s shape for the UI files.
export function seaBackendAssetMap() {
  const out = {};
  for (const rel of collectBackendSourceFiles()) out[`src/${rel}`] = join(REPO_ROOT, rel);
  return out;
}
