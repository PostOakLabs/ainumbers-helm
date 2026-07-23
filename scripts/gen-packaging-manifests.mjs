#!/usr/bin/env node
// Fills the winget/homebrew/npm packaging templates from a signed
// dist/release-manifest.json (HELM-H8). Run AFTER release-manifest.mjs so
// the sha256 values baked into these manifests are exactly what the release
// signing key attested to — never recomputed independently here.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, cpSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = process.env.HELM_RELEASE_DIST_DIR || join(ROOT, "dist");
const PACKAGING_SRC = join(ROOT, "packaging");
const PACKAGING_OUT = join(DIST, "packaging");

function sha256For(subject, name) {
  const entry = subject.find((s) => s.name === name);
  if (!entry) throw new Error(`gen-packaging-manifests: no release artifact named ${name}`);
  return entry.digest.sha256;
}

function fillTemplate(text, tokens) {
  return Object.entries(tokens).reduce((t, [k, v]) => t.replaceAll(`{{${k}}}`, v), text);
}

function walkTemplates(dir) {
  let out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(walkTemplates(p));
    else if (entry.name.endsWith(".template")) out.push(p);
  }
  return out;
}

function main() {
  const statement = JSON.parse(readFileSync(join(DIST, "release-manifest.json"), "utf8"));
  const { version } = statement.predicate;
  const subject = statement.subject;

  const tokens = {
    VERSION: version,
    SHA256_WINDOWS_X64: sha256For(subject, "windows-x64/helmd.exe"),
    SHA256_MACOS_ARM64: sha256For(subject, "macos-arm64/helmd"),
    SHA256_MACOS_X64: sha256For(subject, "macos-x64/helmd"),
    SHA256_LINUX_X64: sha256For(subject, "linux-x64/helmd"),
  };

  const templates = walkTemplates(PACKAGING_SRC);
  let written = 0;
  for (const templatePath of templates) {
    const rel = relative(PACKAGING_SRC, templatePath).replace(/\.template$/, "");
    const outPath = join(PACKAGING_OUT, rel);
    mkdirSync(dirname(outPath), { recursive: true });
    const filled = fillTemplate(readFileSync(templatePath, "utf8"), tokens);
    writeFileSync(outPath, filled);
    written++;
  }

  console.log(`gen-packaging-manifests: wrote ${written} manifest(s) for v${version} -> ${PACKAGING_OUT}`);
}

main();
