#!/usr/bin/env node
// Gate: fails when a vendored-looking file has no data/credits-registry.json entry
// covering it. Detects vendoring by convention used across the 4 repos:
//   - a `*.bundle.mjs`/`*.bundle.js` filename (anywhere)
//   - a singular `vendor/` path segment (anywhere) — the third-party staging
//     convention used by postject, pkijs, chainlink-protos-cre
//   - a plural `vendored/` path segment, UNLESS it's inside a known first-party
//     cross-repo MIRROR root for this repo (MIRROR_ROOTS below) — helm's
//     hub/vendored/ocg/ and hub/vendored/anchor-suite/ are first-party mirrors
//     ("vendored" here means "mirrored", not "third-party"; see each root's own
//     MANIFEST.json). Genuine third-party content nested inside a mirror root
//     (a bundle file, or a nested singular vendor/ dir) is still caught by the
//     other two signals.
// Usage: node scripts/check-credits-coverage.mjs <repo-id>
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '..', '..');
const repoId = process.argv[2];
if (!repoId || !['repo', 'mcp-apps-poc', 'helm', 'anchor-suite'].includes(repoId)) {
  console.error('Usage: node scripts/check-credits-coverage.mjs <repo-id>  (repo-id: repo|mcp-apps-poc|helm|anchor-suite)');
  process.exit(1);
}

const registry = JSON.parse(readFileSync(path.join(ROOT, 'data', 'credits-registry.json'), 'utf8'));
const covered = registry.vendored
  .filter(v => v.repos.includes(repoId))
  .flatMap(v => (v.paths && v.paths[repoId]) || [])
  .map(p => p.replace(/\\/g, '/'));

// First-party cross-repo mirror roots, per repo — "vendored" by naming
// convention, not by license. Only the plural vendored/ signal is suppressed
// inside these; bundle files and nested singular vendor/ dirs still trigger.
const MIRROR_ROOTS = {
  repo: [],
  'mcp-apps-poc': [],
  // ui/vendored/ is mostly first-party ports (see ui/vendored/PORT.md +
  // MANIFEST.json) — excluding it from the generic plural signal means a
  // non-bundle third-party leaf file dropped in there without a bundle suffix
  // (e.g. today's qrcodegen.js) won't self-flag; it's covered by an explicit
  // registry path instead. Re-tighten if that trade-off ever bites.
  helm: ['hub/vendored/ocg/', 'hub/vendored/anchor-suite/', 'ui/vendored/'],
  'anchor-suite': [],
}[repoId];

const EXCLUDE_DIRS = new Set(['.git', 'node_modules', '.wt', '.wrangler', '.claude-worktrees', '.worktrees', 'bundled', 'dist']);
const VENDOR_SINGULAR_RE = /(^|\/)vendor\//i;
const VENDOR_PLURAL_RE = /(^|\/)vendored\//i;
const BUNDLE_FILE_RE = /\.bundle\.(mjs|js)$/i;

function inMirrorRoot(relPath) {
  return MIRROR_ROOTS.some(root => relPath.startsWith(root));
}

function isCovered(relPath) {
  return covered.some(c => relPath === c || relPath.startsWith(c.endsWith('/') ? c : c + '/') || (c.endsWith('/') && relPath.startsWith(c)));
}

function walk(dir, relDir, out) {
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const name of entries) {
    if (EXCLUDE_DIRS.has(name)) continue;
    const full = path.join(dir, name);
    const rel = relDir ? `${relDir}/${name}` : name;
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) {
      walk(full, rel, out);
    } else {
      const isBundleFile = BUNDLE_FILE_RE.test(name);
      const isVendorSingular = VENDOR_SINGULAR_RE.test(rel);
      const isVendorPlural = VENDOR_PLURAL_RE.test(rel) && !inMirrorRoot(rel);
      if (isBundleFile || isVendorSingular || isVendorPlural) out.push(rel);
    }
  }
}

const found = [];
walk(ROOT, '', found);

// CREDITS-BUNDLE-HEURISTIC-1 (ported from the site repo's gate of the same name):
// the *.bundle.mjs filename check is FILENAME-ONLY and cannot tell genuinely
// vendored third-party code from an original-authorship shared kernel composition
// module (ACCT-INFRA-KERNELS-BUILD-SPEC.md §4.1 mandates that exact suffix for any
// shared, inline-consumed composition module regardless of authorship — the mirror
// re-pin to site main 9a64b622 brought the site's _amort/_dtree/_ruleversion
// originals into hub/vendored/ocg/kernels). A bundle file not covered by the
// credits registry may instead be covered by
// scripts/original-authorship-bundle-allowlist.json with a mandatory written
// `reason` — never a silent exemption, and never a substitute for real vendoring
// credit (genuinely third-party bundles, e.g. _noble-ed25519.bundle.mjs, stay on
// the credits-registry path).
const ORIGINAL_ALLOWLIST_PATH = path.join(ROOT, "scripts", "original-authorship-bundle-allowlist.json");
const originalAllowlist = existsSync(ORIGINAL_ALLOWLIST_PATH)
  ? JSON.parse(readFileSync(ORIGINAL_ALLOWLIST_PATH, "utf8"))
  : {};

const allowlistErrors = [];
for (const [rel, entry] of Object.entries(originalAllowlist)) {
  if (rel === "_README") continue;
  if (typeof entry?.reason !== "string" || !entry.reason.trim()) {
    allowlistErrors.push(`${rel}: original-authorship-bundle-allowlist.json entry has no written \`reason\` — every original-authorship bundle exemption must say why it is original`);
  }
}

const isOriginalAuthorshipBundle = (relPath) => {
  const entry = originalAllowlist[relPath];
  return !!entry && typeof entry.reason === "string" && entry.reason.trim().length > 0;
};

const uncovered = found.filter(f => !isCovered(f) && !isOriginalAuthorshipBundle(f));

if (allowlistErrors.length || uncovered.length) {
  if (uncovered.length) {
    console.error(`check-credits-coverage: ${uncovered.length} vendored-looking file(s) with no data/credits-registry.json entry (and no original-authorship-bundle-allowlist.json entry) for repo "${repoId}":`);
    for (const f of uncovered) console.error(`  - ${f}`);
    console.error('Either add an entry to data/credits-registry.json (vendored[].paths.' + repoId + ') and re-run scripts/gen-credits.mjs if this is genuinely vendored,');
    console.error('or add an entry with a written `reason` to scripts/original-authorship-bundle-allowlist.json if this is an original-authorship .bundle.mjs composition module.');
  }
  if (allowlistErrors.length) {
    console.error(`check-credits-coverage: ${allowlistErrors.length} invalid original-authorship-bundle-allowlist.json entr${allowlistErrors.length === 1 ? 'y' : 'ies'}:`);
    for (const e of allowlistErrors) console.error(`  - ${e}`);
  }
  process.exit(1);
}

console.log(`check-credits-coverage: ${found.length} vendored-looking file(s) scanned, all covered by the registry.`);
