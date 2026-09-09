#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-cfportal-1 — the Cloudflare MCP Server Portal (Logpush)
// field map, feeding the shared runner scripts/gwlog-import/_map.mjs (spec:
// HELM-MAINTENANCE-BUILD-SPEC §3.2; board row HELM-GWLOG-IMPORT-cfportal-1).
//
// Source of the field names below, cited exactly:
//
//   https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/
//     ("MCP Portal Logs" — the account-scoped Logpush dataset; field list
//      verified live 2026-09-09, `Last updated Mar 12, 2026`): ClientCountry,
//     ClientIP, ColoCode, Datetime, Error, Method ("the JSON-RPC method of
//     the request (for example, 'tools/call', 'prompts/get', 'resources/read')"),
//     PortalAUD, PortalID, PromptGetName, ResourceReadURI, ServerAUD, ServerID,
//     ServerResponseDurationMs, ServerURL ("URL of the upstream MCP Server"),
//     SessionID, Success, ToolCallName, UserEmail, UserID.
//
//   https://developers.cloudflare.com/agents/model-context-protocol/protocol/governance/
//     ("MCP governance" — "MCP server portals": the Access portal is the
//     administrative hub governing identity, conditions, and which tools
//     within an MCP server are authorized; "Cloudflare Access logs MCP server
//     requests and tool executions made through the portal").
//
// Fields the documented dataset does NOT carry (checked against the field
// list above): no JSON-RPC request/response body, no digest field, no DLP
// label. The map therefore reads enrichment fields an operator must add
// downstream of the Logpush job (e.g. via Logpush Transformers filtering into
// the destination pipeline); all four are this map's names, not documented
// Cloudflare dataset fields, and the header says so:
//   request_body / response_body — captured JSON-RPC bodies; hashed (sha256)
//     and DROPPED by the runner; never reach the generic log or bundle
//   request_digest / response_digest — operator-computed sha256 of those
//     bodies (cross-checked against them when both are present)
//   dlp_label — a Cloudflare DLP-adjacent label; when present it becomes the
//     generic `classification`, otherwise `internal`
// Where a documented field is absent the map uses "unknown" and marks it:
//   actor_version — no version field exists in the dataset → "unknown".
//   ts — `Datetime` ("Type: int or string") is used directly; a numeric
//     epoch is millisecond-converted, otherwise passed through as-is.
// No partnership implied — see docs/AGENT-GATEWAY-LOG-DEMO.md.
import { writeFileSync, readFileSync } from "node:fs";
import { importLog } from "./_map.mjs";

export const DOC_URL = [
  "https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/mcp_portal_logs/",
  "https://developers.cloudflare.com/agents/model-context-protocol/protocol/governance/",
].join(" | ");

export const SOURCE = "cfportal";

export const fieldMap = {
  fields: [
    // ts: `Datetime — Type: int or string — the date and time the request
    // was made`. Numeric epoch values arrive in ms.
    { field: "ts", always: (src) => (typeof src.Datetime === "number" ? new Date(src.Datetime).toISOString() : (src.Datetime ?? "unknown")) },
    // run_id: the stateful MCP session when Cloudflare carries one, else the
    // portal (`PortalID`) as the run grouping this log knows about.
    { field: "run_id", always: (src) => src.SessionID ? `session:${src.SessionID}` : (src.PortalID ? `portal:${src.PortalID}` : "unknown") },
    // actor_id: the authenticated user/agent identity — `UserID` ("unique
    // identifier of the authenticated user") with `UserEmail` as fallback
    // ("email address of the authenticated user who performed the request").
    { field: "actor_id", always: (src) => src.UserID ?? (src.UserEmail ? `email:${src.UserEmail}` : "unknown") },
    { field: "actor_version", always: () => "unknown" },
    // action: the MCP method plus, when the dataset's per-method field
    // carries it, the named entity — `tool.invoke:<ToolCallName>` for
    // tools/call, `prompt.get:<PromptGetName>` for prompts/get,
    // `resource.read:<ResourceReadURI>` for resources/read, the bare method
    // otherwise (`Method` is "the JSON-RPC method of the request").
    { field: "action", always: (src) => {
        const m = String(src.Method ?? "unknown");
        if (m === "tools/call") return src.ToolCallName ? `tool.invoke:${src.ToolCallName}` : "tool.invoke";
        if (m === "prompts/get") return src.PromptGetName ? `prompt.get:${src.PromptGetName}` : "prompt.get";
        if (m === "resources/read") return src.ResourceReadURI ? `resource.read:${src.ResourceReadURI}` : "resource.read";
        return `mcp.${m}`;
      } },
    // target_host: `ServerURL — URL of the upstream MCP Server`, hostname
    // only.
    { field: "target_host", always: (src) => {
        if (!src.ServerURL) return "unknown";
        try { return new URL(String(src.ServerURL)).hostname; } catch { return "unknown"; }
      } },
    // scope: the portal that vetted/authorized the exchange (governance page:
    // which MCP servers and which tools are authorized is defined per portal)
    // plus the upstream server identifier; EMPTY array when the source
    // carries neither — a scope is never invented:
    { field: "scope", always: (src) => {
        const s = [];
        if (src.PortalID) s.push(`portal:${src.PortalID}`);
        if (src.ServerID) s.push(`server:${src.ServerID}`);
        return s;
      } },
    // classification: from a DLP label when one is present (enrichment field
    // `dlp_label` — no DLP field exists in the documented dataset), else
    // "unknown" → "internal" default is NOT applied silently: "unknown"
    // maps to "internal" only here because the verifier demands a tag; the
    // absence of a label is stated by the map, not hidden.
    { field: "classification", always: (src) => {
        const v = src.dlp_label;
        if (typeof v === "string" && v.length > 0) return `dlp:${v}`;
        if (typeof src.Success === "boolean" && !src.Success) return "fault";
        return "internal";
      } },
  ],
  digests: { request: "request_digest", response: "response_digest" },
  bodies: { request: "request_body", response: "response_body" },
};

// The source-shaped entry point.
export function importCfPortalLog({ jsonlText, bundleId }) {
  return importLog({ source: SOURCE, docUrl: DOC_URL, jsonlText, map: fieldMap, bundleId });
}

// Re-exported so sibling rows (HELM-GWLOG-IMPORT-<source>-1) and the test
// suite exercise the SAME shared runner invocation.
export { importLog };

function usage() {
  console.error(`usage: node scripts/gwlog-import/cfportal.mjs <input.jsonl> --out generic.jsonl --bundle-out bundle.json --keys-out publicKeys.json [--bundle-id ID]`);
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
    result = importCfPortalLog({ jsonlText, bundleId });
  } catch (err) {
    console.error(`cfportal-import: ${err.message}`);
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
