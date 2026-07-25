"use strict";
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// SEA main script — MUST be CommonJS (no `import`/`export`). Node's single
// executable runner compiles the main file as a plain CJS Script; an ESM
// entry (what index.mjs is) fails immediately with "Cannot use import
// statement outside a module" and, because helmd.exe is a console-subsystem
// binary, the window a double-click opens closes again before anyone can
// read that error — that IS the "helmd does nothing" bug (HELM-WIN-INSTALL-1).
//
// Fix: the real backend (hub/*.mjs, ~537 files) is embedded as SEA assets
// (see sea-source-manifest.mjs). On first run of a given build, this shim
// extracts them once to a per-version cache dir under HELM_HOME, then
// dynamically `import()`s the real index.mjs from there — dynamic import()
// is available from CommonJS, so this file itself never needs `import`.
// Running outside SEA (plain `node hub/sea-entry.cjs`, or via sea-entry
// during dev) just imports index.mjs straight off disk — no extraction step.
const path = require("node:path");
const os = require("node:os");
const fs = require("node:fs");
const { pathToFileURL } = require("node:url");

function stateHome() {
  return process.env.HELM_HOME || path.join(os.homedir(), ".helm");
}

function isRunningAsSea() {
  try {
    return require("node:sea").isSea();
  } catch {
    return false;
  }
}

// Extraction is idempotent per version: if the destination dir already has
// every file the manifest expects, skip re-writing (fast on the common
// "already installed" path). A version bump gets its own dir, so an
// in-place upgrade can't serve a mix of two builds' files.
function extractRuntime(sea, version) {
  const manifest = JSON.parse(sea.getAsset("src-manifest", "utf8"));
  const destRoot = path.join(stateHome(), "_runtime", version);
  for (const rel of manifest) {
    const outPath = path.join(destRoot, ...rel.split("/"));
    if (fs.existsSync(outPath)) continue;
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    const buf = Buffer.from(sea.getAsset(`src/${rel}`));
    fs.writeFileSync(outPath, buf);
  }
  return destRoot;
}

async function main() {
  let entryUrl;
  if (isRunningAsSea()) {
    const sea = require("node:sea");
    const version = sea.getAsset("src-version", "utf8");
    const destRoot = extractRuntime(sea, version);
    entryUrl = pathToFileURL(path.join(destRoot, "hub", "index.mjs")).href;
  } else {
    entryUrl = pathToFileURL(path.join(__dirname, "index.mjs")).href;
  }
  await import(entryUrl);
}

main().catch((err) => {
  // A startup crash must be readable, not a console window that flashes
  // shut — see HELM-WIN-INSTALL-1. Windows Explorer double-click still
  // closes the window the instant the process exits, so pause here rather
  // than exiting immediately; `helmd start` from an existing terminal just
  // eats one extra keypress.
  console.error("helmd: fatal startup error");
  console.error(err && err.stack ? err.stack : err);
  if (process.stdin.isTTY) {
    console.error("\nPress Enter to close this window...");
    process.stdin.once("data", () => process.exit(1));
    process.stdin.resume();
  } else {
    process.exit(1);
  }
});
