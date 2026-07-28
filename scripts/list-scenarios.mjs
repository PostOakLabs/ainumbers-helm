#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// CLI wrapper for hub/templates.mjs + hub/packs.mjs (HELM-SAMPLE-1). No
// daemon, no config, no account — reads the committed packs/ catalog the
// same way scripts/export-bpmn.mjs does. Surfaces the curated, sample-data
// templates first (the ones `run-template.mjs` can run end to end), then
// every other compiled pack by workflow_id (runnable via `export-bpmn` or
// the browser UI, not yet template-wired).
import { listTemplates } from "../hub/templates.mjs";
import { listPacks } from "../hub/packs.mjs";

const json = process.argv.includes("--json");
const templates = listTemplates();
const templateIds = new Set(templates.map((t) => t.workflow_id));
const otherPacks = listPacks().filter((p) => !templateIds.has(p.workflow_id));

if (json) {
  console.log(JSON.stringify({ templates, other_packs: otherPacks }));
  process.exit(0);
}

console.log(`Scenarios with sample data (run with: helmd run-template <slug>)\n`);
for (const t of templates) {
  console.log(`  ${t.slug}`);
  console.log(`    ${t.title} — ${t.blurb}`);
  console.log(`    workflow_id: ${t.workflow_id}\n`);
}
console.log(`${otherPacks.length} other compiled packs (no sample data yet — see workflow_id, export with: helmd export-bpmn <workflow_id>)`);
