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
  return [...loadAll().values()].map(({ workflow_id, name, outcome }) => ({ workflow_id, name, outcome }));
}

export function getPack(workflowId) {
  return loadAll().get(workflowId) ?? null;
}
