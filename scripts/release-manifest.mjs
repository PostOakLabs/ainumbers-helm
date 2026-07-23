#!/usr/bin/env node
// Builds + dual-signs the release manifest (HELM-H8, D10) over every
// artifact in dist/: SEA binaries per platform + packaging manifests.
// Statement subject = one entry per artifact (name, sha256, size). Predicate
// carries the version + platform list. Run in CI after all matrix build jobs
// have deposited their artifacts into dist/.
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { buildStatement, emitEnvelope, helmPredicateType } from "../hub/envelope.mjs";
import { loadReleaseKeysFromEnv } from "../hub/release-keys.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = process.env.HELM_RELEASE_DIST_DIR || join(ROOT, "dist");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function walk(dir) {
  let out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(walk(p));
    else out.push(p);
  }
  return out;
}

function main() {
  const pkgVersion = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
  const version = process.env.HELM_RELEASE_VERSION || pkgVersion;

  if (process.env.HELM_RELEASE_VERSION && process.env.HELM_RELEASE_VERSION !== pkgVersion) {
    console.error(
      `release-manifest: tag version v${process.env.HELM_RELEASE_VERSION} does not match package.json version ${pkgVersion} — refusing to sign a mismatched release`
    );
    process.exit(1);
  }

  if (!existsSync(DIST)) {
    console.error(`release-manifest: no dist/ directory — run build-sea.mjs for each platform first`);
    process.exit(1);
  }
  const files = walk(DIST).filter((f) => !f.endsWith("release-manifest.json") && !f.endsWith("release-manifest.dsse.json"));
  if (files.length === 0) {
    console.error("release-manifest: dist/ is empty — nothing to sign");
    process.exit(1);
  }

  const subject = files
    .map((f) => ({
      name: relative(DIST, f).replace(/\\/g, "/"),
      digest: { sha256: sha256(f) },
      size: statSync(f).size,
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const statement = buildStatement({
    subject,
    predicateType: helmPredicateType("release-manifest"),
    predicate: {
      version,
      node_version: process.version,
      platforms: [...new Set(subject.map((s) => s.name.split("/")[0]).filter(Boolean))],
    },
  });

  const keys = loadReleaseKeysFromEnv();
  const envelope = emitEnvelope(statement, keys);

  writeFileSync(join(DIST, "release-manifest.json"), JSON.stringify(statement, null, 2) + "\n");
  writeFileSync(join(DIST, "release-manifest.dsse.json"), JSON.stringify(envelope, null, 2) + "\n");

  console.log(`release-manifest: signed ${subject.length} artifact(s) for v${version}`);
}

main();
