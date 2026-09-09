#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-agentgateway-1 — the agentgateway field map, feeding the
// shared runner scripts/gwlog-import/_map.mjs (spec: HELM-MAINTENANCE-BUILD-SPEC
// §3.2). Source of the field names below, cited exactly:
//
//   https://agentgateway.dev/docs/standalone/main/documentation/observability/access-logs/view/
//     ("View and customize logs" — the agentgateway access-log page; the older
//      /docs/.../security/access-logging/ paths this row was staged against
//      now live under /docs/<standalone|kubernetes>/.../observability/
//      access-logs/ and are 404 as of 2026-09-09; sitemap-verified, not
//      guessed)
//     — built-in stdout access-log fields: `gateway`, `listener`, `route`,
//       `endpoint`, `src.addr`, `http.method`, `http.host`, `http.path`,
//       `http.version`, `http.status`, `protocol`, `duration`; `gen_ai.*` on
//       LLM traffic and `mcp.*` on MCP traffic; JSON output via
//       `config.logging.format: json`; operator-added CEL fields, e.g.
//       `user_id` from `request.headers["x-user-id"]`, are the documented
//       enrichment hook for identity-style fields; `response.code` is the
//       documented filter field for HTTP status.
//   https://agentgateway.dev/docs/standalone/main/reference/cel/cel-context/
//     (the CEL reference, stated by agentgateway to be the source of truth
//     for nested fields) — the `request` object carries method / path /
//     pathAndQuery / uri / host / headers / scheme / startTime / endTime /
//     version / body; the `mcp` object carries methodName / sessionId /
//     tool / prompt / resource / task.
//
// Where a field is absent from these docs the map uses "unknown" and marks it:
//   actor_version — no agent/tool version field is documented on either page
//     → always "unknown".
//   actor_id — nothing documented beyond the operator-added `user_id` CEL
//     example above → "unknown" unless that field is present.
//   ts (JSON-format key name) — the docs document the console (key=value)
//     format with a leading RFC-3339 timestamp but do not document the JSON
//     key name; the map prefers the documented CEL `request.startTime` and
//     otherwise falls back to "unknown" (callers wanting a concrete instant
//     can emit one via the documented accessLog `add:` CEL hook).
// No partnership implied — see docs/AGENT-GATEWAY-LOG-DEMO.md.
import { writeFileSync, readFileSync } from "node:fs";
import { importLog } from "./_map.mjs";

export const DOC_URL = [
  "https://agentgateway.dev/docs/standalone/main/documentation/observability/access-logs/view/",
  "https://agentgateway.dev/docs/standalone/main/reference/cel/cel-context/",
].join(" | ");

export const SOURCE = "agentgateway";

export const fieldMap = {
  fields: [
    // ts: see header note — CEL `request.startTime` is documented; the JSON
    // access-log timestamp key is not documented by name.
    { field: "ts", always: (src) => src["request.startTime"] ?? src.request?.startTime ?? src.ts ?? "unknown" },
    { field: "run_id", always: (src) => src["mcp.sessionId"] ? `mcp:${src["mcp.sessionId"]}` : (src.route ? `route:${src.route}` : "unknown") },
    { field: "actor_id", src: "user_id", transform: (v, src) => v === "unknown" && src["request.headers"]?.["x-user-id"] ? src["request.headers"]["x-user-id"] : v },
    { field: "actor_version", always: () => "unknown" },
    // MCP tool calls surface in the documented CEL `mcp` object
    // (`mcp.methodName` arrives as the operator-added access-log field
    // `mcp.methodName` in the mcp.* field family); LLM/HTTP traffic records
    // the HTTP verb like the demo's generic `http.get` convention:
    { field: "action", always: (src) => src["mcp.methodName"] ? "tool.invoke" : `http.${String(src["http.method"] ?? src["request.method"] ?? "GET").toLowerCase()}` },
    { field: "target_host", src: "http.host", transform: (v, src) => v === "unknown" && src["request.host"] ? String(src["request.host"]).split(":")[0] : v },
    // scope from route/policy attributes when present — access logs carry the
    // `route` attribute; the map records it as type-scoped, and leaves an
    // EMPTY array rather than inventing a scope the source does not carry:
    { field: "scope", always: (src) => src.route ? [`route:${src.route}`] : [] },
    { field: "classification", always: () => "internal" },
  ],
  // Digests: agentgateway documents no digest fields on access logs; the
  // documented `accessLog.add` CEL hook (with the documented sha256.encode
  // CEL function) is the enrichment path. Enrichment field names chosen here:
  //   request_digest / response_digest
  // Bodies: the documented CEL `request` object carries `body` (buffered);
  // response bodies reach logs only when operators add them. If a body is
  // present, the runner hashes it (sha256) and DROPS it before anything is
  // written. Neither body nor digest → refused with reason `no_digest`.
  digests: { request: "request_digest", response: "response_digest" },
  bodies: { request: "request.body", response: "response.body" },
};

// The source-shaped entry point.
export function importAgentGatewayLog({ jsonlText, bundleId }) {
  return importLog({ source: SOURCE, docUrl: DOC_URL, jsonlText, map: fieldMap, bundleId });
}

// Re-exported so sibling rows (HELM-GWLOG-IMPORT-<source>-1) and the test
// suite exercise the SAME shared runner invocation.
export { importLog };

function usage() {
  console.error(`usage: node scripts/gwlog-import/agentgateway.mjs <input.jsonl> --out generic.jsonl --bundle-out bundle.json --keys-out publicKeys.json [--bundle-id ID]`);
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
    result = importAgentGatewayLog({ jsonlText, bundleId });
  } catch (err) {
    console.error(`agentgateway-import: ${err.message}`);
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
