#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// GWLOG-DEMO-1 (board row): converts a GENERIC, VENDOR-NEUTRAL agent-gateway
// action log (JSON-lines, one action per line, schema below) into a signed,
// hash-chained, offline-verifiable Helm evidence bundle — using ONLY the
// existing H3 journal + H7 bundle machinery (hub/journal.mjs, hub/checkpoint.mjs,
// hub/bundle.mjs). No new envelope member, no new schema, no new object kind.
//
// Every action-log line maps to TWO existing shapes:
//   1. A journal entry (kind "execution_state") — proves append-order + gives
//      the demo a real hash-chained journal to tamper against.
//   2. A sealed "connector_attestation" bundle object (schema/objects/
//      connector_attestation.schema.json) — trust label connector_asserted:
//      the gateway ASSERTED the action happened, exactly the epistemic claim
//      a third-party action log actually supports (no kernel re-execution,
//      no human review — those get their own trust labels elsewhere).
//
// Input schema (one JSON object per line, additional vendor-specific fields
// are ignored — this converter reads ONLY the fields below):
//   ts               ISO-8601 instant the action executed              (required)
//   run_id           logical run/session grouping id                   (required)
//   actor_id         id of the acting agent/tool (vendor's own id, unchanged) (required)
//   actor_version    agent/tool version string, "unknown" if untracked (required)
//   action           operation name, e.g. "tool.invoke", "http.get"    (required)
//   target_host      host/service acted upon                          (required)
//   scope            array of permission scopes granted for the action (required)
//   request_digest   sha256:<hex> digest of the request payload (NEVER raw payload) (required)
//   response_digest  sha256:<hex> digest of the response payload (NEVER raw payload) (required)
//   classification   data classification tag, e.g. "internal"/"public" (required)
//
// Usage:
//   node scripts/gwlog-to-bundle.mjs <input.jsonl> --out bundle.json --keys-out publicKeys.json [--bundle-id ID]
//
// Offline by construction: reads one file, writes two files, zero network
// calls, zero daemon/state-dir dependency (raw in-memory keys + in-memory
// journal, same pattern scripts/gen-verify-demo-fixture.mjs already uses).
import { readFileSync, writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync } from "node:crypto";
import { ml_dsa44 } from "../hub/vendored/ocg/kernels/_proof.mjs";
import { openJournal, appendEntry } from "../hub/journal.mjs";
import { buildCheckpoint } from "../hub/checkpoint.mjs";
import { assembleBundle, browserPublicKeys } from "../hub/bundle.mjs";

const REQUIRED_FIELDS = [
  "ts", "run_id", "actor_id", "actor_version", "action",
  "target_host", "scope", "request_digest", "response_digest", "classification",
];

const SHA256REF_RE = /^sha256:[0-9a-f]{64}$/;

export function parseActionLogLine(line, lineNo) {
  let row;
  try {
    row = JSON.parse(line);
  } catch (err) {
    throw new Error(`line ${lineNo}: not valid JSON — ${err.message}`);
  }
  for (const f of REQUIRED_FIELDS) {
    if (!(f in row)) throw new Error(`line ${lineNo}: missing required field "${f}"`);
  }
  if (!Array.isArray(row.scope)) throw new Error(`line ${lineNo}: "scope" must be an array`);
  if (!SHA256REF_RE.test(row.request_digest)) throw new Error(`line ${lineNo}: "request_digest" must match sha256:<hex64>`);
  if (!SHA256REF_RE.test(row.response_digest)) throw new Error(`line ${lineNo}: "response_digest" must match sha256:<hex64>`);
  return row;
}

export function readActionLog(jsonlText) {
  return jsonlText
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l, i) => parseActionLogLine(l, i + 1));
}

// contract_digest (schema field, borrowed from the live-connector shape) has
// no live connector contract to point at here — a converter has no vault. It
// is pinned to the digest of THIS converter's documented input schema (the
// REQUIRED_FIELDS list above, JCS-free plain string form), so it is
// reproducible and means something concrete: "the schema this bundle was
// built against", not a placeholder of all zeros.
const CONTRACT_DIGEST = `sha256:${createHash("sha256").update(REQUIRED_FIELDS.join(",")).digest("hex")}`;

// workflow_manifest_digest is required by evidence_bundle_manifest.schema.json
// and connector_attestation.schema.json alike; a gateway-log demo has no
// Helm-authored workflow manifest to point at, so it is pinned to the digest
// of the source log file itself — the one artifact this bundle is actually
// a claim about.
export function buildGwlogBundle(jsonlText, { bundleId = "bundle-gwlog-demo-1" } = {}) {
  const rows = readActionLog(jsonlText);
  if (rows.length === 0) throw new Error("action log is empty — nothing to convert");

  const runId = rows[0].run_id;
  const workflowManifestDigest = `sha256:${createHash("sha256").update(jsonlText).digest("hex")}`;
  const keys = { ed25519: generateKeyPairSync("ed25519"), mldsa44: ml_dsa44.keygen() };

  const db = openJournal(":memory:");
  const specs = rows.map((row, i) => {
    appendEntry(db, {
      streamId: row.run_id,
      kind: "execution_state",
      runId: row.run_id,
      entry: {
        period_start: row.ts,
        period_end: row.ts,
        reference_db_version: "gwlog-demo-1",
        triggering_input_digest: row.request_digest,
        humans_involved: [],
        step_id: `gwlog:${i}`,
        state: "completed",
      },
    });

    return {
      kind: "connector_attestation",
      subject: [{ name: "response_payload", digest: { sha256: row.response_digest.replace(/^sha256:/, "") } }],
      predicate: {
        run_id: row.run_id,
        workflow_manifest_digest: workflowManifestDigest,
        recorded_at: row.ts,
        connector_id: row.actor_id,
        connector_version: row.actor_version,
        contract_digest: CONTRACT_DIGEST,
        operation: row.action,
        scope: row.scope,
        endpoint_host: row.target_host,
        payload_digest: row.response_digest,
        classification: row.classification,
      },
    };
  });

  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors: [] });
  db.close();

  const bundle = assembleBundle({
    bundleId,
    runId,
    workflowManifestDigest,
    specs,
    checkpoints: [checkpoint],
    anchorsRef: [],
    keys,
  });

  return { bundle, publicKeys: browserPublicKeys(keys) };
}

function usage() {
  console.error(`usage: node scripts/gwlog-to-bundle.mjs <input.jsonl> --out bundle.json --keys-out publicKeys.json [--bundle-id ID]

Converts a generic, vendor-neutral agent-gateway action log (JSON-lines) into
a signed, hash-chained, offline-verifiable Helm evidence bundle. See the field
list documented at the top of this file, or docs/AGENT-GATEWAY-LOG-DEMO.md.

Verify the result offline with the existing verifier, unchanged:
  node scripts/verify.mjs bundle.json --keys publicKeys.json`);
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes("-h") || rawArgs.includes("--help")) {
    usage();
    process.exit(0);
  }
  let outPath, keysOutPath, bundleId;
  const positional = [];
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === "--out") { outPath = rawArgs[++i]; continue; }
    if (a === "--keys-out") { keysOutPath = rawArgs[++i]; continue; }
    if (a === "--bundle-id") { bundleId = rawArgs[++i]; continue; }
    positional.push(a);
  }
  const [inputPath] = positional;
  if (!inputPath || !outPath || !keysOutPath) {
    usage();
    process.exit(2);
  }

  const jsonlText = readFileSync(inputPath, "utf8");
  let result;
  try {
    result = buildGwlogBundle(jsonlText, bundleId ? { bundleId } : {});
  } catch (err) {
    console.error(`gwlog-to-bundle: ${err.message}`);
    process.exit(2);
  }

  writeFileSync(outPath, JSON.stringify(result.bundle, null, 2));
  writeFileSync(keysOutPath, JSON.stringify(result.publicKeys, null, 2));
  console.log(`Wrote ${outPath} (${result.bundle.objects.length} sealed action(s)) and ${keysOutPath}`);
}

import { pathToFileURL } from "node:url";
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
