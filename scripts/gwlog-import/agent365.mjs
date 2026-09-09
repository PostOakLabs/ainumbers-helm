#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-agent365-1 — the Microsoft Agent 365 / Purview audit
// export field map, feeding the shared runner scripts/gwlog-import/_map.mjs
// (spec: HELM-MAINTENANCE-BUILD-SPEC §3.2). Source of the field names below,
// cited exactly:
//
//   https://learn.microsoft.com/en-us/purview/audit-copilot
//     ("Audit logs for Copilot and AI applications" — the Purview audit page
//      for Copilot / AI-application activity, incl. agents surfaced through
//      Agent 365; the fields below are from its property tables):
//     - `AgentId` — "Unique identifier for an agent. The string can also
//       include details about the category of agent involved in the
//       interaction" (e.g. `CopilotStudio.Declarative.<guid>`); this is the
//       agent identifier field the demo keys on — pass-through of the export
//       value, not re-derived. Values like `CopilotStudio.CustomEngine.<id>`
//       often carry the Entra object id of the agent.
//     - `AgentVersion` — "The version number or version ID of the agent".
//     - `Operation` — "the name of the activity that was audited"
//       (`CopilotInteraction` for user interactions).
//     - `RecordType` / `Workload` (`Copilot`, `ConnectedAIApp`, `AIApp`)
//       and `AppHost` — the datasource / host classification.
//     - `Messages` — "details about the prompt and response messages within
//       the Copilot interaction. A single audit record typically contains a
//       prompt-response pair".
//   https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema/
//     (the Office 365 Management Activity API common schema — the shared
//     record envelope every Purview audit export carries): `Id` (audit
//     record id), `RecordType`, `CreationTime` ("date and time in
//     Coordinated Universal Time (UTC) when the audit log record was
//     generated"), `Operation`, `OrganizationId`, `UserId`, `UserKey`,
//     `Workload`, `ResultStatus`.
//
// Purview audit records carry no request/response digest fields, and the
// interaction content lives in one doc'd `Messages` object per record (a
// prompt-response pair) — so the map:
//   - builds both side bodies from `AuditData.Messages` (hashed by the
//     runner, and DROPPED before anything is written; the raw interaction
//     content never reaches the bundle);
//   - accepts an operator-side pre-computed digest via
//     `AuditData.request_digest` / `AuditData.response_digest` (enrichment
//     field names this map defines; a record carrying a digest next to its
//     `Messages` is cross-checked against sha256(body) and refused with
//     `digest_mismatch` if it no longer matches);
//   - REFUSES a line whose record carries neither `AuditData.Messages` nor
//     an enrichment digest with reason `no_digest`.
// Where a field is absent from these docs the map uses "unknown" / an empty
// array and marks it:
//   scope — the audit docs above do not document a permissions/roles field
//     in the AI-interaction record; the map records
//     `AuditData.Permissions`/`AuditData.Roles` if an export carries them
//     and otherwise leaves an EMPTY array rather than inventing a scope.
//   target_host — `AuditData.AppHost` (the documented host-application
//     property), falling back to the common-schema `Workload`; neither →
//     "unknown".
// No partnership implied — see docs/AGENT-GATEWAY-LOG-DEMO.md.
import { writeFileSync, readFileSync } from "node:fs";
import { importLog } from "./_map.mjs";

export const DOC_URL = [
  "https://learn.microsoft.com/en-us/purview/audit-copilot",
  "https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema/",
].join(" | ");

export const SOURCE = "agent365";

export const fieldMap = {
  fields: [
    { field: "ts", src: "CreationTime" },
    { field: "run_id", src: "Id" },
    { field: "actor_id", src: "AuditData.AgentId" },
    { field: "actor_version", src: "AuditData.AgentVersion" },
    { field: "action", src: "Operation" },
    { field: "target_host", src: "AuditData.AppHost", transform: (v) => v === "unknown" ? "unknown" : String(v).split(":")[0] },
    { field: "scope", always: (src) => {
        const d = src.AuditData ?? {};
        if (Array.isArray(d.Permissions)) return d.Permissions.map(String);
        if (Array.isArray(d.Roles)) return d.Roles.map(String);
        return [];
      } },
    { field: "classification", always: () => "internal" },
  ],
  digests: { request: "AuditData.request_digest", response: "AuditData.response_digest" },
  bodies: { request: "AuditData.Messages", response: "AuditData.Messages" },
};

// Purview export records carry AuditData as a JSON *object*; some exports
// serialize it as a JSON *string*. Normalize before mapping so the map is
// honest about the doc'd shape either way.
function normalizeAuditData(line) {
  if (line.AuditData && typeof line.AuditData === "string") {
    const copy = { ...line };
    try { copy.AuditData = JSON.parse(line.AuditData); return copy; }
    catch { return line; }
  }
  return line;
}

// The source-shaped entry point.
export function importAgent365Log({ jsonlText, bundleId }) {
  const normalized = jsonlText
    .split("\n")
    .map((l) => {
      const t = l.trim();
      if (!t) return null;
      let src;
      try { src = JSON.parse(t); }
      catch (err) { throw new Error(`gwlog(agent365): not valid JSON — ${err.message}`); }
      return JSON.stringify(normalizeAuditData(src));
    })
    .filter((l) => l !== null)
    .join("\n") + (jsonlText.trim() ? "\n" : "");
  return importLog({ source: SOURCE, docUrl: DOC_URL, jsonlText: normalized, map: fieldMap, bundleId });
}

// Re-exported so sibling rows (HELM-GWLOG-IMPORT-<source>-1) and the test
// suite exercise the SAME shared runner invocation.
export { importLog };

function usage() {
  console.error(`usage: node scripts/gwlog-import/agent365.mjs <input.jsonl> --out generic.jsonl --bundle-out bundle.json --keys-out publicKeys.json [--bundle-id ID]`);
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes("-h") || rawArgs.includes("--help")) { usage(); process.exit(0); }
  let outPath, bundleOutPath, keysOutPath, bundleId;
  const positional = [];
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === "--out") { outPath = rawArgs[++i]; continue; }
    if (a === "--bundle-out") { bundleOutPath = rawArgs[++i]; continue; }
    if (a === "--keys-out") { keysOutPath = rawArgs[++i]; continue; }
    if (a === "--bundle-id") { bundleId = rawArgs[++i]; continue; }
    positional.push(a);
  }
  const [inputPath] = positional;
  if (!inputPath || !outPath || !bundleOutPath || !keysOutPath) { usage(); process.exit(2); }
  const jsonlText = readFileSync(inputPath, "utf8");
  let result;
  try {
    result = importAgent365Log({ jsonlText, bundleId });
  } catch (err) {
    console.error(`agent365-import: ${err.message}`);
    process.exit(2);
  }
  writeFileSync(outPath, result.jsonl);
  writeFileSync(bundleOutPath, JSON.stringify(result.bundle, null, 2));
  writeFileSync(keysOutPath, JSON.stringify(result.publicKeys, null, 2));
  console.log(
    `Wrote ${outPath} (${result.rows.length} generic action(s), ${result.droppedBodies.length} raw body pair(s) hashed and dropped), ${bundleOutPath}, ${keysOutPath}`
  );
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
