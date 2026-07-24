// Google OAuth scope lint (HELM-P3-U4, P3-D5). drive.readonly and the bare
// "drive" scope are both Google RESTRICTED scopes requiring an annual CASA
// security assessment ($500-4.5k/yr) — dead at Helm's $0 budget. Phase-1's
// H6 connector used drive.readonly; this gate exists so neither the browser
// nor daemon connector layer can silently reintroduce it (or the even
// broader bare "drive" scope) after the P3-D5/P3-DEC-2 migration to
// drive.file.
//
// Pure predicate + a small structural scanner, kept separate from the CLI
// entrypoint (check-google-scopes.mjs) so the logic is unit-testable without
// touching the filesystem, and so the test file's own fixture strings (which
// necessarily contain the forbidden scope names) never trip the real repo
// scan.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Both the bare form (as this repo's contract JSON files write it) and the
// full scope-URL form (as some SDKs/docs write it) are checked — a scope is
// forbidden if it names drive.readonly or the whole-Drive scope by EITHER
// spelling. Exact-match only (never substring/includes) so "drive.file" and
// "https://www.googleapis.com/auth/drive.file" are never caught by a naive
// "contains drive" check.
const FORBIDDEN_EXACT = new Set([
  "drive.readonly",
  "drive",
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/drive",
]);

export function isForbiddenGoogleScope(scope) {
  return FORBIDDEN_EXACT.has(scope);
}

export function findForbiddenScopes(scopes) {
  return (scopes ?? []).filter(isForbiddenGoogleScope);
}

// Pulls string array literals out of a `"scopes": [...]` (JSON) or
// `scopes: [...]` / `defaultScopes: [...]` (JS object literal) occurrence in
// source text. Deliberately simple regex, not a parser: this repo's own
// house style always writes scope arrays as a flat list of quoted strings on
// this key, so a parser would be solving a problem that doesn't exist here
// (D2 zero-dep discipline).
const SCOPES_ARRAY_RE = /\b(?:scopes|defaultScopes)\s*:\s*\[([^\]]*)\]/g;

export function extractScopeArraysFromSource(text) {
  const arrays = [];
  let m;
  while ((m = SCOPES_ARRAY_RE.exec(text))) {
    const items = [...m[1].matchAll(/["']([^"']*)["']/g)].map((mm) => mm[1]);
    arrays.push(items);
  }
  return arrays;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "vendored", ".wt", ".worktrees"]);
// This module and its CLI/test necessarily contain the forbidden scope
// strings as data (to define/verify the check itself) — excluded from the
// scan they define, same reasoning as any linter not linting its own rule
// table.
const SELF_EXCLUDE = new Set(["google-scope-lint.mjs", "google-scope-lint.test.mjs", "check-google-scopes.mjs"]);

function walk(dir) {
  let out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(walk(p));
    else if ((entry.name.endsWith(".mjs") || entry.name.endsWith(".json")) && !SELF_EXCLUDE.has(entry.name)) out.push(p);
  }
  return out;
}

// Scans every tracked .mjs/.json file under `root` for scope arrays and
// reports any file that names a forbidden Google scope. Returns a list of
// { file, scope } violations (empty = clean).
export function scanRepoForForbiddenGoogleScopes(root) {
  const violations = [];
  for (const file of walk(root)) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    let scopeArrays;
    if (file.endsWith(".json")) {
      try {
        const data = JSON.parse(text);
        scopeArrays = Array.isArray(data?.scopes) ? [data.scopes] : [];
      } catch {
        scopeArrays = [];
      }
    } else {
      scopeArrays = extractScopeArraysFromSource(text);
    }
    for (const arr of scopeArrays) {
      for (const scope of findForbiddenScopes(arr)) {
        violations.push({ file, scope });
      }
    }
  }
  return violations;
}
