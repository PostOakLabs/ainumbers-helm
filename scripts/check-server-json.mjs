#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// check-server-json.mjs — HELM-REGISTRY-LIST-1 gate for the MCP Registry
// listing (`server.json` at the repo root).
//
// Why this exists beside `mcp-publisher validate` (measured 2026-09-17):
// mcp-publisher 1.7.9 AND 1.8.1 both report `✅ valid` for a packages[]
// entry with registryType "github", because the official server.schema.json
// (2025-12-11) constrains registryType only via description/examples —
// there is no hard enum in any published schema version (or in the next
// draft at docs/reference/server-json/draft/). Registry CONSUMERS, however,
// recognize exactly npm, pypi, oci, nuget, mcpb — which is how PR #270's
// registryType "github" entry survived a green `mcp-publisher validate` and
// had to be caught by human review (Tim, 2026-09-17: DROP it). This gate
// encodes the constraints the schema leaves open, so the defect class can
// never go green in CI again:
//
//   1. $schema is the pinned 2025-12-11 schema URL (no silent schema drift).
//   2. name is the io.github.PostOakLabs/helm listing; repository.url is
//      this repo.
//   3. version is a bare GA CalVer (HELM-CALVER-1: YYYY.M.D, no `v`, no
//      -rc) and every package entry carries the same version.
//   4. every packages[] entry has a registry-consumable registryType
//      (npm | pypi | oci | nuget | mcpb), a 64-hex fileSha256, and — for
//      registryType "mcpb" — an identifier that is exactly the release
//      asset path the release workflow's mcpb job produces:
//      .../releases/download/<version>/helm-<version>.mcpb
//   5. transport is streamable-http on a loopback (127.0.0.1) endpoint.
//   6. remotes is [] — loopback-only, no remote endpoint claims (row fence).
//   7. the description says so (the row requires the loopback-only posture
//      be VISIBLE to a registry reader, not just true).
//
// Full JSON-Schema validation is deliberately NOT re-implemented here; it
// stays delegated to `mcp-publisher validate` (pinned download) in CI.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SCHEMA_PIN = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";
export const REGISTRY_TYPES = ["npm", "pypi", "oci", "nuget", "mcpb"];
const LOOPBACK_URL = /^http:\/\/127\.0\.0\.1(:\d{1,5})?(\/|$)/;
const CALVER = /^\d{4}\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;

export function checkServerJson(doc) {
  const errs = [];
  const err = (path, msg) => errs.push(`${path}: ${msg}`);

  if (doc.$schema !== SCHEMA_PIN) {
    err("$schema", `expected the pinned 2025-12-11 schema URL (${SCHEMA_PIN}), got ${JSON.stringify(doc.$schema)}`);
  }
  if (doc.name !== "io.github.PostOakLabs/helm") {
    err("name", `expected "io.github.PostOakLabs/helm", got ${JSON.stringify(doc.name)}`);
  }
  if (doc.repository?.url !== "https://github.com/PostOakLabs/ainumbers-helm") {
    err("repository.url", "must be https://github.com/PostOakLabs/ainumbers-helm");
  }
  if (typeof doc.version !== "string" || !CALVER.test(doc.version)) {
    err("version", `must be a bare GA CalVer (YYYY.M.D), got ${JSON.stringify(doc.version)}`);
  }
  if (typeof doc.description !== "string" || !/loopback/i.test(doc.description)) {
    err("description", 'must state the loopback-only posture (say "loopback" explicitly)');
  }
  if (typeof doc.description === "string" && !/no remote endpoints/i.test(doc.description)) {
    err("description", 'must disclaim remote endpoints ("no remote endpoints")');
  }
  if (!Array.isArray(doc.remotes) || doc.remotes.length !== 0) {
    err("remotes", "must be [] — the daemon is loopback-only, no remote endpoint claims");
  }

  if (!Array.isArray(doc.packages) || doc.packages.length === 0) {
    err("packages", "must be a non-empty array (the .mcpb release bundle entry)");
  } else {
    doc.packages.forEach((pkg, i) => {
      const at = `packages[${i}]`;
      if (!REGISTRY_TYPES.includes(pkg.registryType)) {
        err(at, `registryType ${JSON.stringify(pkg.registryType)} is not a registry-consumable value (allowed: ${REGISTRY_TYPES.join(", ")}) — "github" and other ad-hoc strings are what MCP Registry clients cannot resolve (Tim 2026-09-17)`);
      }
      if (pkg.version !== doc.version) {
        err(`${at}.version`, `must equal the top-level version ${JSON.stringify(doc.version)}, got ${JSON.stringify(pkg.version)}`);
      }
      if (typeof pkg.fileSha256 !== "string" || !SHA256_HEX.test(pkg.fileSha256)) {
        err(`${at}.fileSha256`, "must be 64 lowercase hex chars");
      }
      if (pkg.registryType === "mcpb") {
        const want = `https://github.com/PostOakLabs/ainumbers-helm/releases/download/${doc.version}/helm-${doc.version}.mcpb`;
        if (pkg.identifier !== want) {
          err(`${at}.identifier`, `must be the release asset the release workflow's mcpb job attaches (${want}), got ${JSON.stringify(pkg.identifier)}`);
        }
      }
      const t = pkg.transport;
      if (!t || t.type !== "streamable-http") {
        err(`${at}.transport.type`, `must be "streamable-http", got ${JSON.stringify(t?.type)}`);
      }
      if (!t || typeof t.url !== "string" || !LOOPBACK_URL.test(t.url)) {
        err(`${at}.transport.url`, `must be a loopback (127.0.0.1) http URL, got ${JSON.stringify(t?.url)}`);
      }
    });
  }
  return errs;
}

function main() {
  const file = join(HERE, "..", "server.json");
  let doc;
  try {
    doc = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`check-server-json: cannot parse ${file}: ${e.message}`);
    process.exit(1);
  }
  const errs = checkServerJson(doc);
  if (errs.length > 0) {
    console.error(`check-server-json: server.json FAILS the registry-consumer policy (${errs.length} problem${errs.length === 1 ? "" : "s"}):`);
    for (const e of errs) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`check-server-json: server.json OK (${doc.packages.length} package entr${doc.packages.length === 1 ? "y" : "ies"}, registryType(s): ${[...new Set(doc.packages.map((p) => p.registryType))].join(", ")}, version ${doc.version}, loopback-only)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
