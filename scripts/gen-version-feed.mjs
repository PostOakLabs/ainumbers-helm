#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// gen-version-feed.mjs — HELM-P4-F3-VERSIONFEED. Builds the site repo's
// helm/version.json (schema/version_notice.schema.json) from release facts
// passed on the command line. Run only from .github/workflows/release.yml
// on a GA tag — never hand-edit the output, that is the incident this
// script exists to prevent.
//
// Facts only: latest_version, minimum_supported_version (currently equal
// to latest_version — a statement of present support, not a forward
// deprecation-window promise; HELM-PHASE4-BUILD-SPEC.md §4 gate 5 allows
// no standing time-based commitment beyond {VDP SLA, semver discipline}),
// release_url, published_at. No day-based or support-window language.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { validate } from "./lib/schema-validator.mjs";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1 || i + 1 >= process.argv.length) {
    console.error(`gen-version-feed: missing --${name}`);
    process.exit(1);
  }
  return process.argv[i + 1];
}

const version = arg("version");
const publishedAt = arg("published-at");
const releaseUrl = arg("release-url");
const schemaPath = arg("schema");
const outPath = arg("out");

if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error(`gen-version-feed: --version "${version}" is not a bare N.N.N version (no leading "v")`);
  process.exit(1);
}

const feed = {
  latest_version: version,
  minimum_supported_version: version,
  release_url: releaseUrl,
  published_at: publishedAt,
};

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const errs = validate(schema, feed);
if (errs.length) {
  console.error("gen-version-feed: generated feed fails schema validation:");
  errs.forEach((e) => console.error(`  ${e}`));
  process.exit(1);
}

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(feed, null, 2) + "\n");
console.log(`gen-version-feed: wrote ${outPath}`);
