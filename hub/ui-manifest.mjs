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
// (excludes *.test.mjs and fixtures/, which never ship).
const FILES = [
  "helm.html",
  "app.mjs",
  "api.mjs",
  "theme.css",
  "lib/dag-svg.mjs",
  "lib/manifest-dag.mjs",
  "lib/manifest-digest.mjs",
  "lib/to-yaml.mjs",
  "lib/verify-bundle.mjs",
  "lib/verify-envelope.mjs",
  "vendored/der.mjs",
  "vendored/hash.mjs",
  "vendored/proof.mjs",
  "vendored/schema-validator.mjs",
  "vendored/schemas/checkpoint.schema.mjs",
  "vendored/schemas/evidence_bundle_manifest.schema.mjs",
  "views/canvas.mjs",
  "views/choose.mjs",
  "views/connect.mjs",
  "views/operate.mjs",
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
UI_ASSETS.set("/", UI_ASSETS.get("/helm.html"));

// Flat { "ui/<rel>": "<abs path>" } map for sea-config's `assets` field —
// same file list, no second source of truth.
export function seaAssetMap() {
  const out = {};
  for (const rel of FILES) out[`ui/${rel}`] = join(UI_DIR, rel);
  return out;
}
