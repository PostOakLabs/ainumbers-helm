// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// check-server-json.test.mjs — HELM-REGISTRY-LIST-1 gate test. The RED
// case is the exact defect Tim's 2026-09-17 review caught on PR #270: a
// packages[] entry with registryType "github", which `mcp-publisher
// validate` (1.7.9 AND 1.8.1, measured) reports as VALID because the
// official schema constrains registryType only via description/examples.
// This gate must reject it, plus the other fence violations:
//   - non-loopback transport / non-empty remotes (the row's ⛔ No remote
//     endpoint claims fence, made mechanical)
//   - identifier not matching the release asset the release workflow's
//     mcpb job attaches
//   - version drift between the listing and its package entries
//   - stale $schema pin
// The GREEN case is the real server.json in the repo root, so the gate
// cannot drift from the file it guards.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { checkServerJson, SCHEMA_PIN } from "./check-server-json.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const REAL = () => JSON.parse(readFileSync(join(ROOT, "server.json"), "utf8"));

test("GREEN: the repo's real server.json passes the registry-consumer policy", () => {
  const errs = checkServerJson(REAL());
  assert.deepEqual(errs, [], `real server.json must be policy-clean, got: ${errs.join(" | ")}`);
});

test("RED (the #270 defect): registryType \"github\" is rejected", () => {
  const doc = REAL();
  doc.packages.push({
    registryType: "github",
    identifier: `https://github.com/PostOakLabs/ainumbers-helm/releases/download/${doc.version}/helm-cli-${doc.version}.tgz`,
    version: doc.version,
    fileSha256: "a".repeat(64),
    transport: { type: "streamable-http", url: "http://127.0.0.1:4173/mcp" },
  });
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.includes("packages[1]") && e.includes('"github"')), `expected a packages[1] registryType rejection, got: ${errs.join(" | ")}`);
});

test("RED: any registryType outside the registry-documented set is rejected", () => {
  const doc = REAL();
  doc.packages[0].registryType = "goproxy";
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.includes("packages[0]") && e.includes('"goproxy"')), errs.join(" | "));
});

test("RED: non-loopback transport URL is rejected (loopback-only fence)", () => {
  const doc = REAL();
  doc.packages[0].transport.url = "https://helmd.example.com/mcp";
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.includes("packages[0].transport.url") && e.includes("loopback")), errs.join(" | "));
});

test("RED: non-empty remotes is rejected (loopback-only fence)", () => {
  const doc = REAL();
  doc.remotes = [{ type: "streamable-http", url: "https://helmd.example.com/mcp" }];
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e === "remotes: must be [] — the daemon is loopback-only, no remote endpoint claims"), errs.join(" | "));
});

test("RED: mcpb identifier not matching the release workflow's asset path is rejected", () => {
  const doc = REAL();
  doc.packages[0].identifier = `https://github.com/PostOakLabs/ainumbers-helm/releases/download/${doc.version}/helm-cli-${doc.version}.tgz`;
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.includes("packages[0].identifier") && e.includes("helm-")), errs.join(" | "));
});

test("RED: package version drifting from the listing version is rejected", () => {
  const doc = REAL();
  doc.packages[0].version = "2026.9.11";
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.includes("packages[0].version")), errs.join(" | "));
});

test("RED: a non-CalVer listing version is rejected (HELM-CALVER-1)", () => {
  const doc = REAL();
  doc.version = "v2026.9.13";
  doc.packages[0].version = "v2026.9.13";
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e === "version: must be a bare GA CalVer (YYYY.M.D), got \"v2026.9.13\""), errs.join(" | "));
});

test("RED: a drifted $schema pin is rejected", () => {
  const doc = REAL();
  doc.$schema = "https://static.modelcontextprotocol.io/schemas/2025-07-09/server.schema.json";
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.startsWith("$schema:") && e.includes(SCHEMA_PIN)), errs.join(" | "));
});

test("RED: a description that stops claiming the loopback posture is rejected", () => {
  const doc = REAL();
  doc.description = "Local-first control plane daemon (helmd).";
  const errs = checkServerJson(doc);
  assert.ok(errs.some((e) => e.startsWith("description:") && e.includes("loopback")), errs.join(" | "));
});
