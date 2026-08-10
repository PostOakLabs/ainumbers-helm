#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// check-techdoc-citations.mjs — anti-drift gate for the technical design doc.
//
// docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md describes how helmd is built,
// and every claim in it is traceable to a source file (usually a file:line
// citation). Source moves; prose does not. This gate makes that divergence a
// hard failure instead of a slow rot nobody notices.
//
// The manifest docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.citations.json
// records a sha256 of every file the doc cites, as of the last time a human
// re-read the claims against the code. This gate recomputes those digests and
// fails when any cited file changed, naming every changed file.
//
// It also fails when a cited file no longer exists, or when a cited line
// number is past the file's current end. Both silently turn a sourced claim
// into an unsourced one.
//
// Citations are EXTRACTED from the doc, never hand-listed in the manifest. A
// hand list would silently ungate every newly added citation, which is the
// exact failure this gate exists to prevent.
//
// ⛔ THE NOISE IS INTENTIONAL. DO NOT "FIX" IT.
// Whole-file digests mean a typo fix in a cited file reddens this gate even
// though no claim changed. That is the correct trade: fail-loud beats
// silent-false. Two weakenings look tempting and are both wrong:
//   - Hashing only the cited line RANGES. Line ranges shift under unrelated
//     edits above them, so that variant is brittle in exactly the cases where
//     drift matters most.
//   - An ignore-list of "cosmetic" files. There is no way to tell, from a
//     digest, whether an edit touched the behavior a claim rests on.
//
// ⛔⛔ NEVER RE-STAMP AUTOMATICALLY — not here, not in a hook, not "when only
// whitespace changed". A manifest that regenerates itself is a gate that
// always passes, which is strictly worse than no gate because it advertises a
// guarantee it does not provide. Re-stamping is a separate, human-invoked
// command (scripts/stamp-techdoc-citations.mjs), and the PR that re-stamps
// must be the PR that re-verified the claims.
//
// Zero npm deps — node builtins only (STANDING ORDERS #10: never npm).
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(HERE, "..");
export const DOC_REL = "docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md";
export const MANIFEST_REL = "docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.citations.json";

// Directories that hold citable source. A backticked token has to start with
// one of these (or be one of the root files below) to count as a citation, so
// prose like `node:sqlite`, `application/vnd.in-toto+json` or `0600` is not
// mistaken for a path.
const CITABLE_DIRS = /^(hub|ui|bin|scripts|schema|packs|docs|fixtures|packaging|test-support|mcp)\//;
const CITABLE_ROOT_FILES = /^(package\.json|LICENSE|NOTICE|README\.md|SECURITY\.md|llms\.txt)$/;

export function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// package.json's `version` field is written mechanically by
// auto-tag-release.yml every day the repo ships — a value the doc never
// cites (it cites package.json for the Apache-2.0 license declaration and
// the empty `dependencies` object, docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md
// lines 284 and 310). Whole-file hashing package.json therefore reddens this
// gate on every release, on a field with no doc claim resting on it. This is
// NOT the banned "ignore-list of cosmetic files" (that bans guessing which
// files don't matter); it is a single named field, in a single named file,
// proven by grep to carry zero citations, excluded by exact key rather than
// by suspicion.
export function citationDigest(path, abs) {
  if (path === "package.json") {
    const pkg = JSON.parse(readFileSync(abs, "utf8"));
    delete pkg.version;
    return createHash("sha256").update(JSON.stringify(pkg)).digest("hex");
  }
  return sha256File(abs);
}

function isCitablePath(p) {
  if (!CITABLE_DIRS.test(p) && !CITABLE_ROOT_FILES.test(p)) return false;
  return /\.[A-Za-z0-9]+$/.test(p); // must carry a file extension
}

/**
 * Extract every source-file citation from the doc.
 *
 * Recognized shapes, both inside backticks:
 *   `hub/server.mjs`            — file, no line
 *   `hub/server.mjs:1033`       — file, single line
 *   `hub/server.mjs:1037-1054`  — file, line range (the END is what must exist)
 *
 * The doc also writes runs of citations into one file as
 * "(`hub/vault.mjs:32`, `98`, `124`)". Those bare numbers are attached to the
 * most recent path in the SAME paragraph, so they are EOF-checked too. Bare
 * numbers with a leading zero are ignored, because the doc uses `0600` and
 * `0700` for file modes.
 *
 * @returns {Map<string, {maxLine: number|null}>}
 */
export function extractCitations(docText) {
  const cites = new Map();
  const note = (path, line) => {
    if (!cites.has(path)) cites.set(path, { maxLine: null });
    const entry = cites.get(path);
    if (line !== null && (entry.maxLine === null || line > entry.maxLine)) entry.maxLine = line;
  };

  for (const paragraph of docText.split(/\n\s*\n/)) {
    let lastPath = null;
    for (const m of paragraph.matchAll(/`([^`\n]+)`/g)) {
      const token = m[1].trim();

      const asPath = token.match(/^([A-Za-z0-9_./-]+?)(?::(\d+)(?:-(\d+))?)?$/);
      if (asPath && isCitablePath(asPath[1])) {
        lastPath = asPath[1];
        note(lastPath, asPath[3] ? Number(asPath[3]) : asPath[2] ? Number(asPath[2]) : null);
        continue;
      }

      const asContinuation = token.match(/^([1-9]\d+)(?:-([1-9]\d+))?$/);
      if (asContinuation && lastPath) note(lastPath, Number(asContinuation[2] || asContinuation[1]));
    }
  }
  return cites;
}

function lineCount(text) {
  return text.split(/\r?\n/).length;
}

// A vendored pin (OCG's `pinnedSha` in vendor.config.json, Anchor Suite's in
// vendor-anchor.config.json) is a mechanical restatement of a value, not a
// claim about behavior — the file:line citation machinery above is the wrong
// tool for it (whole-file hashing would force a re-stamp on every re-vendor,
// exactly the drift this line used to suffer by hand). So the doc points at
// the config file instead of restating the sha as a literal. This check is
// the backstop: it fails if a hex-looking sha literal ever reappears next to
// "pinned at" in the doc, so the fix (HELM-TECHDOC-PIN-DERIVE-1) can't quietly
// regress back to a hand-maintained literal.
export function checkNoLiteralPin(docText) {
  const issues = [];
  const re = /pinned at `([0-9a-f]{6,40})`/gi;
  for (const m of docText.matchAll(re)) {
    issues.push(
      `doc restates a vendor pin as a literal ("pinned at \`${m[1]}\`") — point at the config file's ` +
        `pinnedSha instead (see HELM-TECHDOC-PIN-DERIVE-1); a literal here goes stale on every re-vendor.`
    );
  }
  return issues;
}

/**
 * Pure checker: returns a list of human-readable failures (empty === green).
 * Split out from the CLI so check-techdoc-citations.test.mjs can drive it
 * against fixtures without shelling out.
 */
export function collectIssues(root, docText, manifest) {
  const issues = [];
  const cites = extractCitations(docText);
  const stamped = new Map((manifest.files || []).map((f) => [f.path, f.sha256]));

  for (const [path, { maxLine }] of [...cites.entries()].sort()) {
    const abs = join(root, path);

    if (!stamped.has(path)) {
      issues.push(`${path}: cited by the doc but NOT in the citation manifest — a new citation is an ungated claim; re-stamp after verifying it.`);
      continue;
    }
    if (!existsSync(abs)) {
      issues.push(`${path}: cited by the doc but the file no longer exists — the claim that cites it is now unsourced.`);
      continue;
    }

    const actual = citationDigest(path, abs);
    if (actual !== stamped.get(path)) {
      issues.push(`${path}: CHANGED since the doc's claims were last verified (stamped ${stamped.get(path).slice(0, 12)}…, on disk ${actual.slice(0, 12)}…).`);
    }

    if (maxLine !== null) {
      const eof = lineCount(readFileSync(abs, "utf8"));
      if (maxLine > eof) {
        issues.push(`${path}: doc cites line ${maxLine} but the file is only ${eof} lines — the citation points past end of file.`);
      }
    }
  }

  for (const path of stamped.keys()) {
    if (!cites.has(path)) {
      issues.push(`${path}: in the citation manifest but the doc no longer cites it — re-stamp to drop the stale entry.`);
    }
  }

  issues.push(...checkNoLiteralPin(docText));

  return issues;
}

function main() {
  const docPath = join(ROOT, DOC_REL);
  const manifestPath = join(ROOT, MANIFEST_REL);

  if (!existsSync(manifestPath)) {
    console.error(`✗ techdoc citations: no ${MANIFEST_REL} — run 'node scripts/stamp-techdoc-citations.mjs' after verifying the doc's claims.`);
    process.exit(1);
  }

  const docText = readFileSync(docPath, "utf8");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const issues = collectIssues(ROOT, docText, manifest);

  if (issues.length) {
    console.error(`✗ techdoc citations: ${issues.length} failure(s) — ${DOC_REL} may no longer describe the code it cites:`);
    for (const issue of issues) console.error(`    - ${issue}`);
    console.error("");
    console.error("  What you owe: re-read the claims in the doc that cite these files, correct");
    console.error("  the prose where the code moved, then re-stamp in the SAME pull request:");
    console.error("      node scripts/stamp-techdoc-citations.mjs");
    console.error("  ⛔ Do not re-stamp without re-reading. The stamp asserts a human checked.");
    process.exit(1);
  }

  console.log(`✓ techdoc citations: ${(manifest.files || []).length} cited file(s) unchanged since stamp ${manifest.stampedAtSha || "(none)"}; no missing files, no past-EOF citations.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
