#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-openclaw-1 — the OpenClaw field map, feeding the shared
// runner scripts/gwlog-import/_map.mjs (spec: HELM-MAINTENANCE-BUILD-SPEC
// §3.2; board row HELM-GWLOG-IMPORT-openclaw-1). The source's log shape is the
// OpenClaw Gateway **file log**: rolling JSON-lines files under /tmp/openclaw/
// (`openclaw-YYYY-MM-DD.log`), documented field names cited exactly:
//
//   https://docs.openclaw.ai/logging/ ("How to read logs" / "File logs
//     (JSONL)"): "Each line in the log file is a JSON object"; entries the
//     CLI and Control UI parse render "time, level, subsystem, message";
//     documented machine-filterable top-level fields — `hostname`, `message`,
//     `agent_id` ("active agent id when the log call carries agent context"),
//     `session_id` ("active session id/key"), `channel`; "OpenClaw preserves
//     the original structured log arguments alongside these fields so existing
//     parsers that read numbered tslog argument keys keep working" (chron-
//     numbered arg keys "0","1",... are preserved on the record); trace
//     correlation writes top-level `traceId`, `spanId`, `parentSpanId`,
//     `traceFlags` when diagnostic trace context is present.
//   https://docs.openclaw.ai/gateway/logging/ ("File-based logger"): the file
//     format is one JSON object per line; verbose file logs carry diagnostic
//     timing records, and the transport-diagnostic lines always emitted at
//     info level — "`[model-fetch]` start and response metadata (provider,
//     API, model, status, latency, and request fields such as method, URL,
//     timeout, proxy, and policy)" — are the documented request-shape hook.
//   Source cross-check (backend package openclaw, src/logging/logger.ts and
//     src/logging/json-console-line.ts as of 2026-09-09): a JSON record
//     preserves the tslog numbered args (a leading JSON-string arg is the
//     structured binding, `_meta.logLevelName` / `_meta.name` / `_meta.date`
//     carry level/subsystem/instant) and a structured binding first arg is
//     recorded as the object under key "0"; the JSON-console envelope uses the
//     `time` / `level` / `subsystem` / `message` keys. The timestamp key on a
//     file-log line is `time` (JSON console envelope) with `_meta.date` as the
//     underlying instant.
//
// Where the docs document NO field the map uses "unknown" and says so:
//   actor_version — no agent/tool version field is documented on the logging
//     pages → always "unknown".
//   target_host — OpenClaw file-log lines carry no host/target field (tool
//     arguments and results are never logged: "It never stores prompts,
//     message bodies, tool arguments, tool results..." — /gateway/audit).
//     `target_host` is read ONLY from sidecar enrichment keys below.
//   scope (tool profile) — logged lines carry no tool-profile field; read
//     only from the sidecar keys, else `channel:` when the documented
//     `channel` field is present, else an EMPTY array (never invented).
// Sidecar enrichment keys this map reads (added by an off-box export pass;
// the importer never trusts or invents them): `tool`, `tool_profile`,
// `tool_target`, `request_digest`, `response_digest`, `request.body`,
// `response.body`. OpenClaw ships no digest fields on log lines — see
// https://docs.openclaw.ai/tools/ for the documented tool surface; digests
// must be computed/exported alongside (same shape the agentgateway row
// documents for its `accessLog.add` hook). Raw sidecar bodies are hashed and
// DROPPED by the runner before anything is written; a line carrying neither a
// digest nor a body is refused with reason `no_digest`; a body-bearing line
// whose digest no longer matches sha256(body) is refused with reason
// `digest_mismatch`. No partnership implied — see docs/AGENT-GATEWAY-LOG-DEMO.md.
import { readFileSync, writeFileSync } from "node:fs";
import { importLog } from "./_map.mjs";

export const DOC_URL = [
  "https://docs.openclaw.ai/logging/",
  "https://docs.openclaw.ai/gateway/logging/",
].join(" | ");

export const SOURCE = "openclaw";

// The tslog numbered-arg structured binding (leading JSON-string arg bound
// under "0", per the source cross-check) and its top-level mirror:
const binding = (src) => src["0"] && typeof src["0"] === "object" ? src["0"] : undefined;

export const fieldMap = {
  fields: [
    // ts: /gateway/logging's JSON envelope key is `time` (source cross-check
    // json-console-line.ts); `_meta.date` is the underlying tslog instant.
    { field: "ts", always: (src) => src.time ?? src["_meta"]?.date ?? src.ts ?? "unknown" },
    // run_id: the documented `session_id` groups a run; fall back to the
    // documented trace-correlation key `traceId`.
    { field: "run_id", always: (src) => src.session_id ? `ses:${src.session_id}` : (src.traceId ? `trace:${src.traceId}` : "unknown") },
    // actor_id = agent id (the documented `agent_id` field):
    { field: "actor_id", src: "agent_id" },
    { field: "actor_version", always: () => "unknown" },
    // action = tool name when the record binds one (sidecar `tool`, or the
    // documented numbered-arg binding); `[model-fetch]` is the documented
    // always-info model-transport hook; everything else is a log record of its
    // documented level (envelope `level`, else `_meta.logLevelName`); the
    // log text may live in the documented flattened `message` field or in the
    // preserved numbered-arg keys.
    {
      field: "action",
      always: (src) => {
        const tool = binding(src)?.tool ?? src.tool;
        if (tool) return `tool.${tool}`;
        const msg = typeof src.message === "string" ? src.message
          : typeof src["1"] === "string" ? src["1"] : "";
        if (msg.startsWith("[model-fetch]")) return "model.fetch";
        const level = src.level ?? src["_meta"]?.logLevelName ?? "info";
        return `log.${String(level).toLowerCase()}`;
      },
    },
    // target_host = the MCP server name or host: sidecar `tool_target` (URL
    // or server name) first, then the documented model-transport `url` field's
    // host, else "unknown" (the file log documents no target host).
    {
      field: "target_host",
      always: (src) => {
        const t = binding(src)?.tool_target ?? src.tool_target;
        if (t) return String(t).startsWith("http") ? String(t).split("/")[2] ?? String(t) : String(t);
        const url = src.url;
        if (typeof url === "string") {
          try { return new URL(url).host; } catch { /* fall through */ }
        }
        return "unknown";
      },
    },
    // scope = tool profile (sidecar `tool_profile`), else the documented
    // `channel` field — otherwise EMPTY, never invented:
    {
      field: "scope",
      always: (src) => {
        const prof = binding(src)?.tool_profile ?? src.tool_profile;
        if (prof) return [`tool-profile:${prof}`];
        if (src.channel) return [`channel:${src.channel}`];
        return [];
      },
    },
    { field: "classification", always: () => "internal" },
  ],
  // OpenClaw's file-log records carry NO digest fields and never carry raw
  // payload bodies (transcript text, audio payloads, turn/call ids, and
  // provider item ids are never copied into the record — /logging; tool
  // arguments/results are never stored — /gateway/audit). Both digest keys and
  // the body keys below are therefore the EXPORT sidecar: an off-box tool
  // hashes the payloads it saw and writes `request_digest`/`response_digest`
  // (or attaches the raw sidecar `request.body`/`response.body`, which the
  // shared runner hashes and DROPS — a raw body never reaches the bundle).
  digests: { request: "request_digest", response: "response_digest" },
  bodies: { request: "request.body", response: "response.body" },
};

// The source-shaped entry point.
export function importOpenClawLog({ jsonlText, bundleId }) {
  return importLog({ source: SOURCE, docUrl: DOC_URL, jsonlText, map: fieldMap, bundleId });
}

// Re-exported so sibling rows (HELM-GWLOG-IMPORT-<source>-1) and the test
// suite exercise the SAME shared runner invocation.
export { importLog };

function usage() {
  console.error(`usage: node scripts/gwlog-import/openclaw.mjs <input.jsonl> --out generic.jsonl --bundle-out bundle.json --keys-out publicKeys.json [--bundle-id ID]`);
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
    result = importOpenClawLog({ jsonlText, bundleId });
  } catch (err) {
    console.error(`openclaw-import: ${err.message}`);
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
