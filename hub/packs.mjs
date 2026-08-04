// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Compiled workflow-pack catalog (HELM-P2-U4): reads the committed,
// generator-produced packs/ directory (helm/scripts/compile-packs.mjs,
// HELM-P2-C1) — never regenerated at runtime, same vendoring discipline as
// kernel-runner.mjs's MANIFEST.json read. Cached for the daemon's process
// lifetime; packs only change via a new build + restart, not while running.
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKS_DIR = join(HERE, "..", "packs");

let cache = null;

function loadAll() {
  if (cache) return cache;
  cache = new Map();
  let files;
  try {
    files = readdirSync(PACKS_DIR);
  } catch {
    return cache; // packs/ not built yet — empty catalog, not a crash
  }
  for (const f of files) {
    if (!f.endsWith(".json") || f === "INDEX.json") continue;
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, f), "utf8"));
    cache.set(pack.workflow_id, pack);
  }
  return cache;
}

export function listPacks() {
  // PACK-MARKER-BUILD-SPEC.md §4.3: the catalog card must surface a pack
  // carrying unverified (browser-tool) step(s) without waiting for the
  // canvas detail fetch — count only, never a coverage percentage.
  return [...loadAll().values()].map(({ workflow_id, name, outcome, manifest }) => ({
    workflow_id,
    name,
    outcome,
    unverifiedStepCount: (manifest?.nodes ?? []).filter((n) => n.verified === false).length,
  }));
}

export function getPack(workflowId) {
  return loadAll().get(workflowId) ?? null;
}
