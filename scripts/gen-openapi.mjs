#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-P4-B2: generates docs/openapi.json from hub/server.mjs's own ROUTES +
// DYNAMIC_ROUTES tables — the SSOT is the dispatcher, never a hand-copied
// list (feedback-ssot-generator-freshness-gate). Descriptions below are the
// only hand-authored part; paths/methods are read straight off the router.
//
// Usage: node scripts/gen-openapi.mjs [--check]
//   (no flag) writes docs/openapi.json
//   --check   regenerates in-memory and exits 1 if the committed file is stale
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ROUTES, DYNAMIC_ROUTES } from "../hub/server.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "docs", "openapi.json");
const VERSION = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;

// Hand-authored per-route docs. Keyed "METHOD /path" (docPath for dynamic
// routes) so a route added to server.mjs without a matching entry here fails
// loudly (build() throws) instead of shipping an undocumented endpoint.
const ROUTE_DOCS = {
  "GET /health": { summary: "Daemon liveness check.", tags: ["Daemon"] },
  "GET /version-check": { summary: "Passive daemon-vs-latest-release version notice (HELM-P4-J4 skew banner).", tags: ["Daemon"] },
  "GET /events": { summary: "Server-Sent Events stream of run progress (optionally ?run_id=).", tags: ["Runs"] },
  "POST /events/ticket": { summary: "Mint a short-lived, single-use ticket for /events — EventSource can't set an Authorization header, so this keeps the durable bearer token out of that one query string (HELM-UX-1 §7.4).", tags: ["Runs"] },
  "POST /vault/connections/begin": { summary: "Start an OAuth PKCE loopback connection flow.", tags: ["Vault"] },
  "GET /vault/connections": { summary: "List connected OAuth providers.", tags: ["Vault"] },
  "GET /vault/connections/flow/{flowId}": { summary: "Poll the status of an in-flight connection flow.", tags: ["Vault"] },
  "POST /vault/connections/{id}/revoke": { summary: "Revoke a connected provider.", tags: ["Vault"] },
  "GET /workflows": { summary: "List available workflows.", tags: ["Workflows"] },
  "GET /templates": { summary: "List available Committee Pack templates.", tags: ["Templates"] },
  "GET /templates/{slug}": { summary: "Fetch one template's detail.", tags: ["Templates"] },
  "GET /workflow-manifest": { summary: "Build a workflow's execution manifest.", tags: ["Workflows"] },
  "POST /run/start": { summary: "Start a workflow run.", tags: ["Runs"] },
  "POST /run/resume": { summary: "Resume a run currently held at a §27.4 accountability gate.", tags: ["Runs"] },
  "GET /run/timeline": { summary: "Fetch a run's step-by-step timeline.", tags: ["Runs"] },
  "POST /pair/redeem": { summary: "Redeem a single-use pairing nonce.", tags: ["Pairing"] },
  "POST /migration/import": { summary: "Import a migration bundle from another daemon.", tags: ["Migration"] },
  "POST /workflows/import": { summary: "Import a workflow export bundle.", tags: ["Workflows"] },
  "GET /kernels/{id}/card": { summary: "Fetch a kernel's read-only decision-table card.", tags: ["Kernels"] },
  "GET /workflows/{id}/euc-entry": { summary: "Fetch a workflow's End-User-Computing register entry.", tags: ["Workflows"] },
  "GET /workflows/{id}/export": { summary: "Export a workflow manifest bundle.", tags: ["Workflows"] },
  "GET /ha/pending": { summary: "List runs held at a §27.4 accountability gate, awaiting human records.", tags: ["Accountability"] },
  "GET /ha/records": { summary: "Fetch the §27.2 accountability record trail for a subject_hash.", tags: ["Accountability"] },
  "GET /ha/slot": { summary: "Fetch the countersignature_slot (maker + checker signatures) for a subject_hash.", tags: ["Accountability"] },
  "POST /ha/records": { summary: "Submit a signed §27.2 accountability record (approval/rejection/override/annotation/role_binding).", tags: ["Accountability"] },
  "POST /ha/replay": { summary: "helmd re-executes a step's kernel and countersigns with replay_verified reflecting whether the hash matched.", tags: ["Accountability"] },
  "GET /autostart": { summary: "Report whether the start-at-sign-in entry and desktop shortcut are installed, and whether the recorded entry still points at a Helm that exists.", tags: ["Daemon"] },
  "POST /autostart": { summary: "Install or remove the start-at-sign-in entry and/or the shortcut. Body {autostart?: boolean, shortcut?: boolean}. The only code path that writes either — helmd never installs them on its own.", tags: ["Daemon"] },
};

function toOperation(method, path) {
  const doc = ROUTE_DOCS[`${method} ${path}`];
  if (!doc) throw new Error(`gen-openapi: no ROUTE_DOCS entry for "${method} ${path}" — add one before regenerating.`);
  const params = [...path.matchAll(/\{([^}]+)\}/g)].map((m) => ({
    name: m[1],
    in: "path",
    required: true,
    schema: { type: "string" },
  }));
  const op = {
    summary: doc.summary,
    tags: doc.tags,
    security: [{ bearerAuth: [] }],
    responses: {
      200: { description: "OK", content: { "application/json": { schema: { type: "object" } } } },
      401: { description: "Missing or invalid bearer token." },
      403: { description: "Host or Origin mismatch (D8 loopback hardening)." },
    },
  };
  if (params.length) op.parameters = params;
  return op;
}

export function buildOpenApiDoc() {
  const paths = {};
  for (const key of Object.keys(ROUTES)) {
    const [method, path] = key.split(" ");
    paths[path] ??= {};
    paths[path][method.toLowerCase()] = toOperation(method, path);
  }
  for (const route of DYNAMIC_ROUTES) {
    paths[route.docPath] ??= {};
    paths[route.docPath][route.method.toLowerCase()] = toOperation(route.method, route.docPath);
  }
  return {
    openapi: "3.0.3",
    info: {
      title: "Helm daemon (helmd) — local REST API",
      version: VERSION,
      description:
        "Loopback-only REST + SSE API served by helmd on 127.0.0.1. Every request must present " +
        "Host: 127.0.0.1:<port>, a matching Origin, and (except /health-adjacent detection routes) " +
        "a Bearer token issued during pairing — see docs/POWER-QUERY-BRIDGE.md and README.md for the " +
        "pairing flow. This document is generated from hub/server.mjs's own route table " +
        "(scripts/gen-openapi.mjs) — never hand-edited.",
    },
    servers: [{ url: "http://127.0.0.1:{port}", variables: { port: { default: "4173" } } }],
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", description: "Pairing token issued by helmd on first run." },
      },
    },
    paths,
  };
}

function main() {
  const doc = buildOpenApiDoc();
  const rendered = JSON.stringify(doc, null, 2) + "\n";
  if (process.argv.includes("--check")) {
    const onDisk = readFileSync(OUT, "utf8");
    if (onDisk !== rendered) {
      console.error("gen-openapi --check: docs/openapi.json is stale — run `node scripts/gen-openapi.mjs` and commit the diff.");
      process.exit(1);
    }
    console.log("gen-openapi --check: docs/openapi.json is fresh");
    return;
  }
  writeFileSync(OUT, rendered);
  console.log(`gen-openapi: wrote ${OUT}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
