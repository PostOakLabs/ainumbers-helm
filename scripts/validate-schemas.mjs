#!/usr/bin/env node
// validate-schemas.mjs — GATE. For every schema/**/*.schema.json, requires a
// sibling fixtures/<same-relative-path>/golden.json (MUST validate) and
// tampered.json (MUST fail validation). Non-zero exit blocks CI.
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "./lib/schema-validator.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_DIR = join(ROOT, "schema");
const FIXTURES_DIR = join(ROOT, "fixtures");

function walkSchemas(dir) {
  let out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(walkSchemas(p));
    else if (entry.name.endsWith(".schema.json")) out.push(p);
  }
  return out;
}

let checked = 0;
let failed = 0;

function report(label, ok, errs) {
  checked++;
  if (ok) { console.log(`✓ ${label}`); return; }
  failed++;
  console.error(`✗ ${label}`);
  errs.slice(0, 20).forEach((e) => console.error(`    ${e}`));
}

const schemaFiles = statSync(SCHEMA_DIR, { throwIfNoEntry: false })?.isDirectory()
  ? walkSchemas(SCHEMA_DIR)
  : [];

if (schemaFiles.length === 0) {
  console.error("validate-schemas: no schema/**/*.schema.json found");
  process.exit(1);
}

for (const schemaPath of schemaFiles) {
  const rel = relative(SCHEMA_DIR, schemaPath);
  const stem = rel.slice(0, -".schema.json".length);
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  const fixtureDir = join(FIXTURES_DIR, stem);

  const goldenPath = join(fixtureDir, "golden.json");
  const tamperedPath = join(fixtureDir, "tampered.json");

  if (!existsSync(goldenPath)) {
    checked++; failed++;
    console.error(`✗ ${stem}: missing fixtures/${stem}/golden.json`);
    continue;
  }
  if (!existsSync(tamperedPath)) {
    checked++; failed++;
    console.error(`✗ ${stem}: missing fixtures/${stem}/tampered.json`);
    continue;
  }

  const golden = JSON.parse(readFileSync(goldenPath, "utf8"));
  const tampered = JSON.parse(readFileSync(tamperedPath, "utf8"));

  const goldenErrs = validate(schema, golden);
  report(`${stem}: golden fixture validates`, goldenErrs.length === 0, goldenErrs);

  const tamperedErrs = validate(schema, tampered);
  report(`${stem}: tampered fixture FAILS validation`, tamperedErrs.length > 0, ["(tampered fixture unexpectedly validated clean)"]);
}

console.log(`\n${checked} checked, ${failed} failed.`);
process.exit(failed ? 1 : 0);
