#!/usr/bin/env node
// CLI entrypoint for the Google OAuth scope lint (HELM-P3-U4, P3-D5). Wired
// into `npm run lint` (see scripts/lint.mjs). Fails the build if any
// connector contract or OAuth provider preset in the repo names
// drive.readonly or the bare "drive" scope — see scripts/lib/google-scope-lint.mjs
// for why those are forbidden.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanRepoForForbiddenGoogleScopes } from "./lib/google-scope-lint.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const violations = scanRepoForForbiddenGoogleScopes(ROOT);

if (violations.length > 0) {
  console.error("GOOGLE SCOPE LINT: forbidden restricted Drive scope found (drive.readonly/drive require a $500-4.5k/yr CASA assessment — use drive.file):");
  for (const v of violations) console.error(`  ${v.file}: "${v.scope}"`);
  process.exit(1);
}

console.log("google-scope-lint: OK");
