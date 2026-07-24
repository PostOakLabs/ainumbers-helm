#!/usr/bin/env node
// CLI wrapper for hub/bpmn-export.mjs (HELM-P4-B3). Usage:
//   node scripts/export-bpmn.mjs <workflow_id> [out.bpmn]
// Writes BPMN 2.0 XML for a compiled pack's workflow manifest to stdout, or
// to the given path if provided.
import { writeFileSync } from "node:fs";
import { getPack } from "../hub/packs.mjs";
import { exportBpmn } from "../hub/bpmn-export.mjs";

const [workflowId, outPath] = process.argv.slice(2);
if (!workflowId) {
  console.error("usage: node scripts/export-bpmn.mjs <workflow_id> [out.bpmn]");
  process.exit(1);
}

const pack = getPack(workflowId);
if (!pack) {
  console.error(`export-bpmn: unknown workflow_id "${workflowId}" (not a compiled pack)`);
  process.exit(1);
}

const xml = exportBpmn(pack.manifest);
if (outPath) {
  writeFileSync(outPath, xml, "utf8");
  console.log(`wrote ${outPath}`);
} else {
  process.stdout.write(xml);
}
