#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// check-internal-lang-leak.mjs — INTERNAL-LANG-LEAK-1.
// This is a PUBLIC repo. Internal governance vocabulary (standing-order
// numbers, named decision-makers, process-internal jargon) reads fine in a
// private workspace doc but has no business in code comments or docs that
// ship to github.com/PostOakLabs/ainumbers-helm. This gate does not object
// to the underlying facts (who decided what) — it objects to citing an
// internal numbering/naming scheme that means nothing to an outside reader.
// Baseline-shielded (mirrors the site repo's check-csp-consistency.mjs
// pattern): a NEW marker not in the baseline -> FAIL. Counts only go down.
// Flags: --init / --update regenerate the baseline from current state.
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname, resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BASELINE = join(ROOT, "scripts", "internal-lang-leak-baseline.json");
const MODE = (process.argv.includes("--init") || process.argv.includes("--update")) ? "update" : "check";

// Comments and docs only. Skip vendored trees entirely (never edited here —
// fixes land upstream and get re-vendored) and build output.
const SCAN_DIRS = [".github", "docs"];
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "vendored"]);
const SCAN_EXTS = new Set([".yml", ".yaml", ".md"]);

const MARKERS = [
  { name: "standing-order-ref",  re: /\bSO #\d+\b/g },
  { name: "standing-order-word", re: /\bSTANDING ORDER\b/gi },
  { name: "tim-executed",        re: /\bTIM-EXECUTED\b/g },
  { name: "tim-decision",        re: /\bTim (?:ruling|decision|approved|says)\b/g },
  { name: "ma-thesis",           re: /\bM&A\b/g },
  { name: "flag-and-wait",       re: /\bflag-and-wait\b/g },
  { name: "orch-process-noun",   re: /\bORCH\b/g },
  { name: "assemble-land-noun",  re: /\bASSEMBLE-LAND\b/g },
  { name: "bare-wu-id",          re: /\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,4}-\d+\b/g },
];

function walk(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(join(dir, e.name), out); }
    else if (e.isFile() && SCAN_EXTS.has(extname(e.name))) out.push(join(dir, e.name));
  }
  return out;
}

const files = SCAN_DIRS.flatMap(d => existsSync(join(ROOT, d)) ? walk(join(ROOT, d)) : []);

let baseline = {};
if (MODE === "check" && existsSync(BASELINE)) {
  baseline = JSON.parse(readFileSync(BASELINE, "utf-8"));
}
const baselineCounts = baseline.counts || {};

const hits = {};
for (const abs of files) {
  const rel = abs.slice(ROOT.length + 1).replace(/\\/g, "/");
  const text = readFileSync(abs, "utf-8");
  for (const { name, re } of MARKERS) {
    const n = (text.match(re) || []).length;
    if (n > 0) (hits[rel] ??= {})[name] = n;
  }
}

if (MODE === "update") {
  writeFileSync(BASELINE, JSON.stringify({ generated: "check-internal-lang-leak.mjs --update", counts: hits }, null, 2) + "\n");
  const total = Object.values(hits).reduce((s, m) => s + Object.values(m).reduce((a, b) => a + b, 0), 0);
  console.log(`check-internal-lang-leak: baseline written — ${total} marker hit(s) across ${Object.keys(hits).length} file(s).`);
  process.exit(0);
}

const regressions = [];
for (const [file, markers] of Object.entries(hits)) {
  const base = baselineCounts[file] || {};
  for (const [name, count] of Object.entries(markers)) {
    if (count > (base[name] || 0)) regressions.push({ file, name, count, baseline: base[name] || 0 });
  }
}

if (regressions.length) {
  console.error(`check-internal-lang-leak: ${regressions.length} NEW internal-governance marker(s) not covered by the baseline:`);
  for (const r of regressions.slice(0, 30)) {
    console.error(`  ${r.file}: ${r.name} (${r.count}, baseline ${r.baseline})`);
  }
  console.error("This is a public repo — drop the internal governance pointer and keep the engineering reason. If this is a deliberate, reviewed exception, run --update.");
  process.exit(1);
}

const healedFiles = Object.keys(baselineCounts).filter(f => !hits[f]);
if (healedFiles.length) {
  console.warn(`check-internal-lang-leak: ${healedFiles.length} baselined file(s) now clean — prune with --update.`);
}

const total = Object.values(hits).reduce((s, m) => s + Object.values(m).reduce((a, b) => a + b, 0), 0);
console.log(`check-internal-lang-leak: 0 new markers (${total} baselined).`);
