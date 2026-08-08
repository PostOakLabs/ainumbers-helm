// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Explicit allowlist of servable UI files (HELM-U4). This Map is the ONLY
// thing static.mjs consults to answer a GET — a request path that isn't a
// key here is a 404, full stop. There is no filesystem-path concatenation
// from request input anywhere in the serving path, so there is no traversal
// surface to construct in the first place. New UI files must be added here
// by hand (also mirrored into scripts/build-sea.mjs / sea-dry-run.mjs's
// sea-config `assets` map so the SEA binary embeds them).
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const UI_DIR = join(HERE, "..", "ui");

const CONTENT_TYPES = {
  html: "text/html; charset=utf-8",
  css: "text/css; charset=utf-8",
  mjs: "text/javascript; charset=utf-8",
};

// ui-relative path for every file the shell app actually loads at runtime
// (excludes *.test.mjs, which never ship). fixtures/verify-demo.mjs DOES
// ship — views/verify.mjs statically imports it for the built-in demo
// buttons, so omitting it 401s the whole ES module graph on load (HELM-P2-B8
// root cause B: a static import 404/401 aborts the entire `<script
// type=module>` before app.mjs's top-level code ever runs, leaving
// `<main>` empty even though mountTokenForm would otherwise render fine).
const FILES = [
  "app.html",
  "app.mjs",
  "api.mjs",
  "theme.css",
  "fixtures/verify-demo.mjs",
  "lib/anchor-browser.mjs",
  "lib/blocked-state.mjs",
  "lib/browser-journal-client.mjs",
  "lib/browser-journal.mjs",
  "lib/canvas-exec-summary.mjs",
  "lib/committee-deck.mjs",
  "lib/committee-pack.mjs",
  "lib/committee-pptx.mjs",
  "lib/company-profile.mjs",
  "lib/connector-browser.mjs",
  "lib/custom-connectors.mjs",
  "lib/dag-svg.mjs",
  "lib/durability-banner.mjs",
  "lib/esc.mjs",
  "lib/ha-crypto.mjs",
  "lib/journal-worker.mjs",
  "lib/euc-html.mjs",
  "lib/manifest-dag.mjs",
  "lib/manifest-digest.mjs",
  "lib/oauth-browser.mjs",
  "lib/pair-form.mjs",
  "lib/presenter.mjs",
  "lib/rfc3161-verify.mjs",
  "lib/tab-meta.mjs",
  "lib/to-yaml.mjs",
  "lib/vault.mjs",
  "lib/vault-crypto.mjs",
  "lib/vault-token-store.mjs",
  "lib/verify-bundle.mjs",
  "lib/verify-envelope.mjs",
  "lib/version-skew.mjs",
  "lib/view-registry.mjs",
  "oauth-callback.html",
  "oauth-callback.mjs",
  "vendored/der.mjs",
  "vendored/der-encode.mjs",
  "vendored/hash.mjs",
  "vendored/pkijs.bundle.mjs",
  "vendored/proof.mjs",
  "vendored/schema-validator.mjs",
  "vendored/schemas/anchor_queue_marker.schema.mjs",
  "vendored/schemas/checkpoint.schema.mjs",
  "vendored/schemas/company_profile.schema.mjs",
  "vendored/schemas/connector_contract.schema.mjs",
  "vendored/schemas/evidence_bundle_manifest.schema.mjs",
  "vendored/tsa-roots.mjs",
  "views/agents.mjs",
  "views/canvas.mjs",
  "views/choose.mjs",
  "views/connect.mjs",
  "views/deadlines.mjs",
  "views/home.mjs",
  "views/learn.mjs",
  "views/matters.mjs",
  "views/operate.mjs",
  "views/register.mjs",
  "views/review.mjs",
  "views/run.mjs",
  "views/verify.mjs",
];

export const UI_ASSETS = new Map();
for (const rel of FILES) {
  const ext = rel.slice(rel.lastIndexOf(".") + 1);
  const contentType = CONTENT_TYPES[ext];
  if (!contentType) throw new Error(`ui-manifest: no content-type mapped for extension ".${ext}" (${rel})`);
  UI_ASSETS.set(`/${rel}`, { rel, seaKey: `ui/${rel}`, contentType });
}
UI_ASSETS.set("/", UI_ASSETS.get("/app.html"));

// Flat { "ui/<rel>": "<abs path>" } map for sea-config's `assets` field —
// same file list, no second source of truth.
export function seaAssetMap() {
  const out = {};
  for (const rel of FILES) out[`ui/${rel}`] = join(UI_DIR, rel);
  return out;
}
