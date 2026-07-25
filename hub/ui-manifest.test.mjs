// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Freshness gate for hub/ui-manifest.mjs's FILES allowlist (HELM-P2-B8 class
// of bug): a file transitively imported from ui/app.mjs but missing from
// UI_ASSETS 401s the WHOLE `<script type=module>` graph before app.mjs's
// top-level boot() ever runs, leaving <main> empty for every view — not
// just the one whose module is missing. Rides scripts/test.mjs (already
// CI-wired) the same way scripts/gen-openapi.test.mjs guards route-table
// drift.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { UI_ASSETS, UI_DIR } from "./ui-manifest.mjs";

const IMPORT_RE = /from\s+["']([^"']+)["']/g;

function relativeImports(absPath) {
  const src = readFileSync(absPath, "utf8");
  const out = [];
  for (const m of src.matchAll(IMPORT_RE)) {
    const spec = m[1];
    if (spec.startsWith("./") || spec.startsWith("../")) out.push(spec);
  }
  return out;
}

// Walks every relative import reachable from ui/app.mjs, following .mjs
// files only (bare/package specifiers and non-.mjs imports are out of
// scope for this allowlist).
function walkImportGraph(entryAbsPath) {
  const seen = new Set();
  const queue = [entryAbsPath];
  while (queue.length) {
    const abs = queue.pop();
    if (seen.has(abs)) continue;
    seen.add(abs);
    for (const spec of relativeImports(abs)) {
      if (!spec.endsWith(".mjs")) continue;
      const next = join(dirname(abs), spec);
      if (!seen.has(next)) queue.push(next);
    }
  }
  return seen;
}

test("hub/ui-manifest.mjs's FILES covers every .mjs reachable from ui/app.mjs", () => {
  const entry = join(UI_DIR, "app.mjs");
  const reached = walkImportGraph(entry);

  const missing = [];
  for (const abs of reached) {
    const rel = abs.slice(UI_DIR.length + 1).split("\\").join("/");
    if (rel.endsWith(".test.mjs")) continue; // never shipped, per ui-manifest.mjs's own comment
    if (!UI_ASSETS.has(`/${rel}`)) missing.push(rel);
  }

  assert.deepEqual(
    missing.sort(),
    [],
    `these files are statically imported (directly or transitively) from ui/app.mjs but missing from hub/ui-manifest.mjs's FILES — add them or the whole module graph 401s on boot: ${missing.join(", ")}`,
  );
});

test("ui/oauth-callback.html is served (own entry page, not reachable via app.mjs's import graph)", () => {
  assert.ok(
    UI_ASSETS.has("/oauth-callback.html"),
    "ui/views/connect.mjs navigates the OAuth provider redirect to oauth-callback.html directly (not via app.mjs's <script type=module> graph) — it must be listed in hub/ui-manifest.mjs's FILES or the OAuth flow 404s",
  );
});
