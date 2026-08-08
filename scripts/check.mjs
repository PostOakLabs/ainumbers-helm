#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// CLI wrapper for hub/check.mjs (HELMCHECK-BUILD-1). Usage:
//   node scripts/check.mjs <pack_id> <input_file> [--out <bundle.json>] [--no-anchor] [--json]
// One-shot process, no daemon, no prior run — see HELM-CHECK-BUILD-SPEC.md.
//
// HELM-CHECK-BATCH-1 (HELM-VERIFY-CLI-BUILD-SPEC.md §2): adds a batch mode,
// triggered by --glob or by more than one positional input file:
//   node scripts/check.mjs <pack_id> --glob "<pattern>" [--out-dir <dir>] [--no-anchor] [--json]
//   node scripts/check.mjs <pack_id> <file1> <file2> ... [--out-dir <dir>] [--no-anchor] [--json]
// The single-positional-file path above is UNCHANGED — batch is strictly
// additive. Batch reuses hub/check.mjs's runCheck() per input, unchanged
// (§2.6) — no second diff/kernel implementation, no new bundle format.
//
// Re-entrancy (phil's open item, carried from HELM-CHECK-BATCH-1's row):
// runCheck() was read end to end before this loop was written. The only
// module-level mutable state anywhere on its call path is hub/packs.mjs's
// `cache` (a Map, populated once and never mutated per-call — a read-only
// catalog of compiled packs keyed by workflow_id, immutable after first
// load) and hub/kernel-runner.mjs's KERNEL_FILE_DIGESTS (a static Map built
// once at import time). hub/keys.mjs's loadOrCreateKeys() reads/writes disk
// on every call but keeps no module-level accumulator that could leak
// between inputs. Nothing on the path keys state by input, accumulates
// across calls, or mutates shared objects returned to a previous caller.
// VERDICT: runCheck() is safely re-entrant for an in-process loop — §2.6's
// in-process design holds. Subprocess-per-input was not required.
import { readFileSync, writeFileSync } from "node:fs";
import { globSync } from "node:fs";
import { basename, dirname, join, resolve, relative, isAbsolute } from "node:path";
import { runCheck, EXIT } from "../hub/check.mjs";

function usage() {
  console.error(`usage:
  helm check <pack_id> <input_file> [--out <bundle.json>] [--no-anchor] [--json]
  helm check <pack_id> --glob "<pattern>" [--out-dir <dir>] [--no-anchor] [--json]
  helm check <pack_id> <file1> <file2> ... [--out-dir <dir>] [--no-anchor] [--json]

Batch mode (--glob, or more than one input file) reuses the single-file
check unattended: it never aborts on a per-file failure, and always exits
nonzero if ANY file failed to run — the summary names every failure by path.
Batch NEVER anchors per file regardless of --no-anchor/--anchor state (an
unattended loop must not turn one fail-soft anchor attempt into an N-request
burst); anchoring a batch run is not implemented in this row — see
HELM-VERIFY-CLI-BUILD-SPEC.md §2.3.`);
}

// §2.5 — resolves `candidate` against cwd and refuses (usage-error exit,
// before any read/write) a result that escapes it. Applied to --out-dir and
// to every --glob match; NOT applied to explicit positional file arguments
// (a caller typing `../foo.json` by hand is the same trust boundary the
// single-file path has always had — this guards against a --glob pattern or
// a derived output path reaching outside the working directory, not against
// a user's own explicit argument).
export function resolveWithinCwd(candidate, label) {
  const cwd = process.cwd();
  const resolved = resolve(cwd, candidate);
  const rel = relative(cwd, resolved);
  if (rel !== "" && (rel.startsWith("..") || isAbsolute(rel))) {
    console.error(`helm check: ${label} "${candidate}" escapes the working directory (resolved: ${resolved})`);
    process.exit(EXIT.USAGE_ERROR);
  }
  return resolved;
}

// Exposed for tests: resolves a --glob pattern to matched paths, each
// path-traversal-checked before any file is touched.
export function resolveGlob(pattern) {
  const matches = globSync(pattern, { cwd: process.cwd() });
  for (const m of matches) resolveWithinCwd(m, `--glob match`);
  return matches;
}

const rawArgs = process.argv.slice(2);
const flags = new Set();
const positional = [];
let outPath;
let outDir;
let globPattern;
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a === "--out") { outPath = rawArgs[++i]; continue; }
  if (a === "--out-dir") { outDir = rawArgs[++i]; continue; }
  if (a === "--glob") { globPattern = rawArgs[++i]; continue; }
  if (a.startsWith("--")) { flags.add(a); continue; }
  positional.push(a);
}
const [packId, ...fileArgs] = positional;
const noAnchor = flags.has("--no-anchor");
const jsonMode = flags.has("--json");

if (!packId) {
  usage();
  process.exit(EXIT.USAGE_ERROR);
}

const isBatch = globPattern !== undefined || fileArgs.length > 1;

if (!isBatch) {
  // --- Single-file path: UNCHANGED behavior (regression-tested). ---------
  const inputPath = fileArgs[0];
  if (!inputPath) {
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
} else {
  // --- Batch path (HELM-CHECK-BATCH-1). -----------------------------------
  if (globPattern !== undefined && fileArgs.length > 0) {
    console.error("helm check: pass either --glob or positional files in batch mode, not both");
    process.exit(EXIT.USAGE_ERROR);
  }

  const resolvedOutDir = outDir !== undefined ? resolveWithinCwd(outDir, "--out-dir") : undefined;
  const files = globPattern !== undefined ? resolveGlob(globPattern) : fileArgs;

  if (files.length === 0) {
    console.error(`helm check: batch mode found no input files${globPattern !== undefined ? ` for glob "${globPattern}"` : ""}`);
    process.exit(EXIT.USAGE_ERROR);
  }

  // §2.3 — batch NEVER anchors per file, unconditionally (--no-anchor/--anchor
  // are not consulted here). Anchoring across a whole batch run as one
  // combined call is parked, not built in this row (see usage() above).
  const results = [];
  for (const filePath of files) {
    let inputFile;
    try {
      inputFile = readFileSync(filePath, "utf8");
    } catch (err) {
      results.push({ file: filePath, ran: false, exitCode: EXIT.USAGE_ERROR, message: `cannot read input_file "${filePath}": ${String(err?.message || err)}` });
      continue;
    }

    let result;
    try {
      result = await runCheck({ packId, inputFile, noAnchor: true });
    } catch (err) {
      results.push({ file: filePath, ran: false, exitCode: EXIT.USAGE_ERROR, message: `unexpected error: ${String(err?.message || err)}` });
      continue;
    }

    if (result.message && !result.report) {
      results.push({ file: filePath, ran: false, exitCode: result.exitCode, message: result.message });
      continue;
    }

    const fileOutPath = resolvedOutDir !== undefined
      ? join(resolvedOutDir, `${basename(filePath)}.check.json`)
      : join(dirname(filePath), `${basename(filePath)}.check.json`);
    writeFileSync(fileOutPath, JSON.stringify(result.bundle, null, 2) + "\n");
    results.push({ file: filePath, ran: true, exitCode: result.exitCode, report: result.report, outPath: fileOutPath });
  }

  // §2.4 — continue-and-summarize: a file that never produced a comparison
  // (read error, unknown pack_id, insufficient input, unexpected throw) is a
  // "failed" file. A file that ran to completion is NOT a failure just
  // because the comparison result was DIFFERS or a scope disagreement —
  // those are valid, reported outcomes, not batch failures.
  const failed = results.filter((r) => !r.ran);

  if (jsonMode) {
    console.log(JSON.stringify({
      pack_id: packId,
      files: results.map((r) => r.ran
        ? { file: r.file, ran: true, exit_code: r.exitCode, result: r.report.result, out: r.outPath }
        : { file: r.file, ran: false, exit_code: r.exitCode, message: r.message }),
      summary: { total: results.length, failed: failed.length },
    }));
  } else {
    console.log(`helm check (batch): pack_id=${packId} files=${results.length}`);
    for (const r of results) {
      if (!r.ran) {
        console.log(`  FAILED  ${r.file}: ${r.message}`);
        continue;
      }
      const label = { match: "MATCH", differs: "DIFFERS", no_assertion: "NO_ASSERTION", scope_mismatch: "SCOPE_MISMATCH" }[r.report.result] ?? r.report.result.toUpperCase();
      console.log(`  ${label}${" ".repeat(Math.max(1, 12 - label.length))}${r.file} -> ${r.outPath}`);
    }
    if (failed.length > 0) {
      console.log(`summary: ${results.length} total, ${failed.length} failed:`);
      for (const r of failed) console.log(`  - ${r.file}: ${r.message}`);
    } else {
      console.log(`summary: ${results.length} total, 0 failed`);
    }
  }

  process.exitCode = failed.length > 0 ? 1 : 0;
}
