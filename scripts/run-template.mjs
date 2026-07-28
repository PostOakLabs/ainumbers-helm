#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// CLI entry point to the EXISTING template runner (HELM-P3-G10's
// hub/templates.mjs + hub/run.mjs + hub/kernel-runner.mjs), reused verbatim —
// this file authors no sample data and no run logic of its own. Same
// daemon-free pattern as scripts/export-bpmn.mjs: an in-memory journal
// (":memory:", same call templates.test.mjs already makes against the real
// engine) stands in for the persistent one a running helmd hub would use, so
// a bundled scenario can be run and inspected without starting the daemon.
//
// Usage:
//   node scripts/run-template.mjs <slug> [--dry-run] [--json]
import { getTemplate, buildTemplateManifest, listTemplates } from "../hub/templates.mjs";
import { openJournal } from "../hub/journal.mjs";
import { executeRun } from "../hub/run.mjs";
import { createKernelStepRunner } from "../hub/kernel-runner.mjs";

const args = process.argv.slice(2).filter((a) => a !== "--dry-run" && a !== "--json");
const dryRun = process.argv.includes("--dry-run");
const json = process.argv.includes("--json");
const [slug] = args;

if (!slug) {
  console.error("usage: node scripts/run-template.mjs <slug> [--dry-run] [--json]");
  console.error(`known slugs: ${listTemplates().map((t) => t.slug).join(", ")}`);
  process.exit(1);
}

const template = getTemplate(slug);
if (!template) {
  console.error(`run-template: unknown slug "${slug}" (not a bundled scenario)`);
  console.error(`known slugs: ${listTemplates().map((t) => t.slug).join(", ")}`);
  process.exit(1);
}

const manifest = buildTemplateManifest(template);
if (!manifest) {
  console.error(`run-template: template "${slug}" points at a workflow_id not in this build's compiled pack catalog`);
  process.exit(1);
}

const db = openJournal(":memory:");
const stepRunner = createKernelStepRunner();
const runId = `cli-${slug}-${dryRun ? "dryrun" : "run"}`;

let result;
try {
  result = await executeRun(db, { runId, manifest, stepRunner, dryRun });
} finally {
  db.close();
}

if (json) {
  console.log(JSON.stringify(result));
} else {
  console.log(`template:       ${slug} (${template.title})`);
  console.log(`workflow_id:    ${template.workflow_id}`);
  console.log(`state:          ${result.state}`);
  console.log(`execution_hash: ${result.executionHash ?? "(none — dry run or not completed)"}`);
  console.log(`steps:`);
  for (const s of result.steps) {
    console.log(`  ${s.step_id}  output_digest=${s.output_digest}`);
  }
}

process.exit(result.state === "completed" ? 0 : 1);
