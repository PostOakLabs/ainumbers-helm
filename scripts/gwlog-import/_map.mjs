#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-GWLOG-IMPORT-* — the shared field-map runner (spec:
// HELM-MAINTENANCE-BUILD-SPEC §3.2; board rows HELM-GWLOG-IMPORT-<source>-1).
//
// A source importer (e.g. agentgateway.mjs) declares a FIELD MAP: for each
// generic field, where it lives in the source's JSON-lines and how it is
// transformed. mapSourceLog() reads the source lines, applies the map, and
// emits the generic shape
//   ts, run_id, actor_id, actor_version, action, target_host, scope[],
//   request_digest, response_digest, classification
// consumed by scripts/gwlog-to-bundle.mjs — which is invoked UNCHANGED to
// seal the generic log into a signed, hash-chained evidence bundle.
//
// Digest policy (never a raw payload in the bundle):
//   - if the source line carries a digest field for a side, it is passed
//     through as-is;
//   - else if it carries a raw body for that side, the body is hashed
//     (sha256) and DROPPED before anything is written;
//   - else the line is REFUSED with reason `no_digest`;
//   - a line carrying BOTH a digest and a body for the same side is
//     cross-checked: a flipped byte in a tampered digest is refused with
//     reason `digest_mismatch`.
// Zero dependencies, node builtins only (the zero-dep.test.mjs gate holds).
import { createHash } from "node:crypto";
import { buildGwlogBundle, parseActionLogLine } from "../gwlog-to-bundle.mjs";

export const GENERIC_FIELDS = [
  "ts", "run_id", "actor_id", "actor_version", "action",
  "target_host", "scope", "request_digest", "response_digest", "classification",
];

// Read a path ("request.startTime" — or a flat source key rendered with the
// dot notation agentgateway's key=value logs use, e.g. "mcp.methodName"):
// direct key first, then nested dot-path traversal.
export function getPath(obj, path, sep = ".") {
  if (obj !== null && typeof obj === "object" && path in obj) return obj[path];
  let cur = obj;
  for (const part of String(path).split(sep)) {
    if (cur === undefined || cur === null) return undefined;
    cur = cur[part];
  }
  return cur;
}

export function hashBody(body) {
  return `sha256:${createHash("sha256").update(String(body)).digest("hex")}`;
}

// map = { fields: [{field, src, transform(value, line)?, always(line)?}, ...],
//         bodies?: {request: srcPath, response: srcPath},
//         digests?: {request: srcPath, response: srcPath},
//         defaults?: {<generic field>: any} — value or the marker "unknown"
//           where the source's docs have no field carrying it (the map says so
//           in the importer's module header, per the row spec). }
export function mapSourceLog({ source, docUrl, jsonlText, map }) {
  if (!Array.isArray(map.fields) || map.fields.length === 0) {
    throw new Error(`gwlog(${source}): field map has no entries`);
  }
  const rows = [];
  const droppedBodies = [];
  const lines = jsonlText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);  const seen = new Set(map.fields.map((f) => f.field));
  for (const f of GENERIC_FIELDS) {
    if (f.endsWith("_digest")) continue; // digests/bodies section handles these
    if (!seen.has(f)) throw new Error(`gwlog(${source}): field map does not map "${f}"`);
  }
  lines.forEach((line, i) => {
    const lineNo = i + 1;
    let src;
    try {
      src = JSON.parse(line);
    } catch (err) {
      throw new Error(`gwlog(${source}): line ${lineNo}: not valid JSON — ${err.message}`);
    }
    const row = {};
    for (const entry of map.fields) {
      if (entry.always) { row[entry.field] = entry.always(src); continue; }
      let v = entry.src !== undefined ? getPath(src, entry.src) : undefined;
      if (v === undefined || v === null) {
        const d = map.defaults?.[entry.field];
        v = d === undefined ? "unknown" : (typeof d === "function" ? d(src) : d);
      }
      if (entry.transform) v = entry.transform(v, src);
      row[entry.field] = v;
    }
    // Digest/body policy per side. Raw bodies are hashed and DROPPED here so
    // they never reach the generic log, the bundle, or the verifier.
    for (const side of ["request", "response"]) {
      const digestPath = map.digests?.[side];
      const bodyPath = map.bodies?.[side];
      const digest = digestPath ? getPath(src, digestPath) : undefined;
      const hasDigest = digest !== undefined && digest !== null;
      const body = bodyPath ? getPath(src, bodyPath) : undefined;
      const hasBody = body !== undefined && body !== null;
      if (!hasDigest && !hasBody) {
        throw new Error(
          `gwlog(${source}): line ${lineNo}: refused with reason no_digest — ` +
          `${side} side carries neither a digest nor a body; raw payloads are never inferred`
        );
      }
      if (hasDigest) {
        if (hasBody) {
          const actual = typeof body === "string" || typeof body === "object"
            ? hashBody(typeof body === "string" ? body : JSON.stringify(body))
            : hashBody(body);
          if (actual !== digest && hashBody(JSON.stringify(body)) !== digest) {
            throw new Error(
              `gwlog(${source}): line ${lineNo}: refused with reason digest_mismatch — ` +
              `${side} digest no longer matches the body it covers (sha256 of body: ${actual})`
            );
          }
        }
        row[`${side}_digest`] = digest;
      } else {
        droppedBodies.push({ line: lineNo, side, sha256: row[`${side}_digest`] = hashBody(body) });
      }
    }
    rows.push(row);
  });
  return { source, docUrl, rows, droppedBodies };
}

// Serialize the mapped rows into the generic JSON-lines text and hand it to
// the UNCHANGED scripts/gwlog-to-bundle.mjs converter.
export function importLog({ source, docUrl, jsonlText, map, bundleId }) {
  const { rows, droppedBodies } = mapSourceLog({ source, docUrl, jsonlText, map });
  const generic = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  // parseActionLogLine is the schema contract of the generic shape — assert
  // every mapped row still passes it before anything is sealed.
  rows.forEach((_, i) => {
    const lines = generic.split("\n").filter((l) => l.length > 0);
    parseActionLogLine(lines[i], i + 1);
  });
  const { bundle, publicKeys } = buildGwlogBundle(generic, {
    bundleId: bundleId ?? `bundle-gwlog-${source}-1`,
  });
  return { source, docUrl, jsonl: generic, rows, droppedBodies, bundle, publicKeys };
}
