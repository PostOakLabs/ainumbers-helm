// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Regression guard for HELM-UIMANIFEST-GUARD-1: a UI file that exists on
// disk and is actually reachable (an <html> entry point, or something
// statically imported from one) but is missing from ui-manifest.mjs's
// allowlist 401s/404s over HTTP, and — per HELM-P2-B8 — a single missing
// static import aborts the ENTIRE module graph before app.mjs's top-level
// code ever runs, so the whole SPA goes blank with no test anywhere else
// catching it (every other test exercises modules directly, not over HTTP).
//
// This derives the "actually requested" set from the real files on disk
// (HTML entry points + their transitive static import graph), NOT from the
// manifest itself — a test that re-reads FILES and checks FILES against
// itself would pass forever while the UI drifted out from under it, which
// is the exact failure this guard exists to catch. It then boots the real
// daemon on a test port and fetches every derived path over HTTP, asserting
// 200 — the stronger of the two options in the WU (module-graph-only would
// catch a missing manifest entry but not a manifest entry pointing at a
// file that no longer exists, or a content-type gap).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-uimanifest-test-"));
process.env.HELM_HOME = TMP;

const PORT = 42102;
const ORIGIN = "null";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { loadOrCreateKeys } = await import("./keys.mjs");
const { createHelmServer } = await import("./server.mjs");
const { UI_ASSETS, UI_DIR } = await import("./ui-manifest.mjs");

const config = loadConfig();
const token = loadOrCreateToken();
const identityKeys = loadOrCreateKeys();
let server;

before(() => {
  server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, identityKeys });
});

after(() => {
  server.close();
  rmSync(TMP, { recursive: true, force: true });
});

function get(pathname) {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: PORT, path: pathname, method: "GET", headers: { Host: `127.0.0.1:${PORT}` } },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode }));
      }
    );
    req.on("error", reject);
    req.end();
  });
}

// posix-ify a UI_DIR-relative path so it matches the "/"-joined keys
// ui-manifest.mjs builds, regardless of host path separator.
function toPosix(p) {
  return p.split("\\").join("/");
}

function resolveImport(fromRel, spec) {
  const dir = dirname(fromRel);
  const joined = dir === "." ? spec.replace(/^\.\//, "") : join(dir, spec);
  return toPosix(joined).replace(/^\.\//, "");
}

// Walk the REAL files on disk: every <script type=module src> / <link
// href> in an HTML entry point, then every `from "./..."` / `from "../..."`
// in each .mjs reached, recursively. This is independent of ui-manifest.mjs
// — it would find a newly-added view's import chain even if nobody ever
// updated the manifest.
function collectReachableAssets() {
  const htmlEntries = readdirSync(UI_DIR).filter((f) => f.endsWith(".html"));
  const visited = new Set();
  const queue = [...htmlEntries];

  while (queue.length) {
    const rel = queue.shift();
    if (visited.has(rel)) continue;
    visited.add(rel);

    const abs = join(UI_DIR, ...rel.split("/"));
    const text = readFileSync(abs, "utf8");

    if (rel.endsWith(".html")) {
      for (const m of text.matchAll(/(?:src|href)="([^"]+\.(?:mjs|css))"/g)) {
        queue.push(resolveImport(rel, m[1]));
      }
    } else if (rel.endsWith(".mjs")) {
      for (const m of text.matchAll(/from\s+["'](\.\.?\/[^"']+)["']/g)) {
        queue.push(resolveImport(rel, m[1]));
      }
    }
  }
  return visited;
}

test("every UI file reachable from an HTML entry point is in the ui-manifest allowlist", () => {
  const reachable = collectReachableAssets();
  const missing = [...reachable].filter((rel) => !UI_ASSETS.has(`/${rel}`));
  assert.deepEqual(missing, [], `reachable but unlisted in ui-manifest.mjs FILES: ${missing.join(", ")}`);
});

test("every ui-manifest allowlist entry is servable over HTTP (200, not 401/404)", async () => {
  const failures = [];
  for (const pathname of UI_ASSETS.keys()) {
    if (pathname === "/") continue; // alias of /helm.html, covered separately
    const { status } = await get(pathname);
    if (status !== 200) failures.push(`${pathname} -> ${status}`);
  }
  assert.deepEqual(failures, [], `manifest entries that don't serve 200: ${failures.join(", ")}`);
});

test("every HTML entry point on disk is servable over HTTP", async () => {
  for (const rel of readdirSync(UI_DIR).filter((f) => f.endsWith(".html"))) {
    const { status } = await get(`/${rel}`);
    assert.equal(status, 200, `${rel} -> ${status}`);
  }
});
