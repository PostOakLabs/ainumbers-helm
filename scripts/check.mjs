#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// CLI wrapper for hub/check.mjs (HELMCHECK-BUILD-1). Usage:
//   node scripts/check.mjs <pack_id> <input_file> [--out <bundle.json>] [--no-anchor] [--json]
// One-shot process, no daemon, no prior run — see HELM-CHECK-BUILD-SPEC.md.
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { runCheck, EXIT } from "../hub/check.mjs";

const rawArgs = process.argv.slice(2);
const flags = new Set(rawArgs.filter((a) => a.startsWith("--")));
const positional = [];
let outPath;
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a === "--out") { outPath = rawArgs[++i]; continue; }
  if (a.startsWith("--")) continue;
  positional.push(a);
}
const [packId, inputPath] = positional;
const noAnchor = flags.has("--no-anchor");
const jsonMode = flags.has("--json");

function usage() {
  console.error("usage: helm check <pack_id> <input_file> [--out <bundle.json>] [--no-anchor] [--json]");
}

if (!packId || !inputPath) {
  usage();
  process.exit(EXIT.USAGE_ERROR);
}

let inputFile;
try {
  inputFile = readFileSync(inputPath, "utf8");
} catch (err) {
  console.error(`helm check: cannot read input_file "${inputPath}": ${String(err?.message || err)}`);
  process.exit(EXIT.USAGE_ERROR);
}

const result = await runCheck({ packId, inputFile, noAnchor });

if (result.message && !result.report) {
  console.error(result.message);
  process.exit(result.exitCode);
}

const finalOutPath = outPath ?? join(dirname(inputPath), `${basename(inputPath)}.check.json`);
writeFileSync(finalOutPath, JSON.stringify(result.bundle, null, 2) + "\n");

if (jsonMode) {
  console.log(JSON.stringify(result.report));
} else {
  const r = result.report;
  console.log(`helm check: pack_id=${r.pack_id} input=${inputPath}`);
  console.log(`  input_digest: ${r.input_digest}`);
  if (r.fields.length === 0) {
    console.log("  (no comparable fields — recompute-only or no overlapping measures)");
  } else {
    for (const f of r.fields) {
      const line = f.match
        ? `  MATCH   ${f.name}`
        : `  DIFFERS ${f.name}: recomputed=${f.recomputed} asserted=${f.asserted}${f.delta !== undefined ? ` (delta=${f.delta})` : ""}`;
      console.log(line);
    }
  }
  console.log(`  result: ${r.result}`);
  console.log(`bundle written: ${finalOutPath}`);
}

process.exitCode = result.exitCode;
