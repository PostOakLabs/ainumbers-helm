// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// build-mcpb.test.mjs — HELM-MCPB-1 gate. Covers the row's done-criteria:
//   - packaging/mcpb/manifest.json validates against the vendored MCPB
//     manifest schema (hub/vendored/mcpb-schema/) — plus negative cases
//     proving the validator actually bites (required/enum/items/$ref)
//   - two builds are byte-identical (deterministic store-only zip)
//   - user_config.token.sensitive === true (and required === true)
//   - the mcp-remote pin in the bundle args is agent-kit/kit.json's pin
//     (single source of truth — never retyped)
//   - zip internals: sorted entries, store-only, fixed DOS mtime
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildMcpb, readZipEntries, validateAgainstSchema } from "./build-mcpb.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PKG = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const KIT = JSON.parse(readFileSync(join(ROOT, "agent-kit", "kit.json"), "utf8"));
const MANIFEST = JSON.parse(readFileSync(join(ROOT, "packaging", "mcpb", "manifest.json"), "utf8"));
const SCHEMA = JSON.parse(
  readFileSync(join(ROOT, "hub", "vendored", "mcpb-schema", "mcpb-manifest-v0.3.schema.json"), "utf8")
);

const TMP = mkdtempSync(join(tmpdir(), "helm-build-mcpb-test-"));
const OUT_A = join(TMP, "a");
const OUT_B = join(TMP, "b");

test("manifest validates against the vendored mcpb schema (HELM-MCPB-1)", () => {
  const errs = validateAgainstSchema(MANIFEST, SCHEMA);
  assert.deepEqual(errs, []);
});

test("validator bites: missing required root field is an error", () => {
  const bad = { ...MANIFEST };
  delete bad.author;
  const errs = validateAgainstSchema(bad, SCHEMA);
  assert.ok(errs.some((e) => e.includes('missing required "author"')), errs.join("; "));
});

test("validator bites: server.type outside the enum is an error", () => {
  const bad = structuredClone(MANIFEST);
  bad.server.type = "ruby";
  const errs = validateAgainstSchema(bad, SCHEMA);
  assert.ok(errs.some((e) => e.includes("$.server.type") && e.includes("enum")), errs.join("; "));
});

test("validator bites: user_config entries need type/title/description", () => {
  const bad = structuredClone(MANIFEST);
  delete bad.user_config.token.title; // required inside additionalProperties schema
  const errs = validateAgainstSchema(bad, SCHEMA);
  assert.ok(errs.some((e) => e.includes("$.user_config.token") && e.includes("required")), errs.join("; "));
});

test("validator bites: args items must be strings (schema items walk)", () => {
  const bad = structuredClone(MANIFEST);
  bad.server.mcp_config.args = ["-y", 42];
  const errs = validateAgainstSchema(bad, SCHEMA);
  assert.ok(errs.some((e) => e.includes("$.server.mcp_config.args[1]") && e.includes("type string")), errs.join("; "));
});

test("validator bites: platform_overrides $refs resolve into the right subschemas", () => {
  const bad = structuredClone(MANIFEST);
  bad.server.mcp_config.platform_overrides = { win32: { command: 42 } };
  const errs = validateAgainstSchema(bad, SCHEMA);
  assert.ok(errs.some((e) => e.includes("command") && e.includes("type string")), errs.join("; "));
});

test("user_config.token is sensitive AND required", () => {
  assert.equal(MANIFEST.user_config.token.sensitive, true);
  assert.equal(MANIFEST.user_config.token.required, true);
});

test("user_config.port defaults to 4173 (the helmd loopback default)", () => {
  assert.equal(MANIFEST.user_config.port.default, 4173);
});

test("bundle args carry the kit.json mcp-remote pin and the exact §3.5 bridge shape", () => {
  const pin = KIT.mcpRemote.pin;
  assert.deepEqual(MANIFEST.server.mcp_config.args, [
    "-y",
    `mcp-remote@${pin}`,
    "http://127.0.0.1:${user_config.port}/mcp",
    "--header",
    "Authorization: Bearer ${user_config.token}",
    "--header",
    "Origin: http://127.0.0.1:${user_config.port}",
  ]);
  assert.equal(MANIFEST.server.mcp_config.command, "npx");
  assert.equal(MANIFEST.server.type, "node");
});

test("two builds are byte-identical, named dist/helm-<version>.mcpb", () => {
  const a = buildMcpb(ROOT, OUT_A);
  const b = buildMcpb(ROOT, OUT_B);
  const expectedName = `helm-${PKG.version}.mcpb`;
  assert.equal(a.name, expectedName);
  assert.equal(b.name, expectedName);
  const shaA = createHash("sha256").update(a.bytes).digest("hex");
  const shaB = createHash("sha256").update(b.bytes).digest("hex");
  assert.equal(shaA, shaB, "two builds of the same tree must be byte-identical");
  // Recorded for the row report: the two equal sha256 values.
  console.log(`build-mcpb.test: build A sha256 = ${shaA}`);
  console.log(`build-mcpb.test: build B sha256 = ${shaB}`);
});

function centralDirectory(bytes) {
  // Walk the end-of-central-directory record backwards to find it (the
  // comment is always empty in our builder, so the EOCD sits at the tail).
  const sig = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  let eocd = -1;
  for (let i = bytes.length - sig.length; i >= 0; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  assert.notEqual(eocd, -1, "end-of-central-directory record not found");
  const count = bytes.readUInt16LE(eocd + 10);
  let off = bytes.readUInt32LE(eocd + 16);
  const entries = [];
  for (let n = 0; n < count; n++) {
    assert.equal(bytes.readUInt32LE(off), 0x02014b50, "central directory signature");
    const entry = {
      method: bytes.readUInt16LE(off + 10),
      dosTime: bytes.readUInt16LE(off + 12),
      dosDate: bytes.readUInt16LE(off + 14),
      crc32: bytes.readUInt32LE(off + 16),
      size: bytes.readUInt32LE(off + 24),
      nameLen: bytes.readUInt16LE(off + 28),
      extraLen: bytes.readUInt16LE(off + 30),
      commentLen: bytes.readUInt16LE(off + 32),
      localHeaderOffset: bytes.readUInt32LE(off + 42),
      name: bytes.slice(off + 46, off + 46 + bytes.readUInt16LE(off + 28)).toString("utf8"),
    };
    entries.push(entry);
    off += 46 + entry.nameLen + entry.extraLen + entry.commentLen;
  }
  return { entries, eocd };
}

test("zip internals: sorted entries, store-only, fixed mtime, valid CRCs", () => {
  const built = buildMcpb(ROOT, join(TMP, "c"));
  const { entries } = centralDirectory(built.bytes);
  const names = entries.map((e) => e.name);
  assert.deepEqual(names, [...names].sort(), "zip entries must be sorted by name");
  for (const e of entries) {
    assert.equal(e.method, 0, `${e.name}: store-only (no compression)`);
    assert.equal(e.dosTime, 0, `${e.name}: fixed DOS time`);
    assert.equal(e.dosDate, 0x2821, `${e.name}: fixed DOS date (2000-01-01)`);
  }
  const parsed = readZipEntries(built.bytes);
  for (const e of parsed) {
    const cd = entries.find((c) => c.name === e.name);
    assert.equal(e.data.length, cd.size, `${e.name}: size matches central directory`);
    assert.ok(cd.crc32 !== 0 || e.data.length === 0, `${e.name}: CRC recorded`);
  }
});

test("zip contents: manifest parses + matches, icon is a PNG, README carries the docs/AGENTS.md Claude section", () => {
  const built = buildMcpb(ROOT, join(TMP, "d"));
  const entries = new Map(readZipEntries(built.bytes).map((e) => [e.name, e.data]));
  assert.deepEqual(
    [...entries.keys()].sort(),
    ["README.md", "icon.png", "manifest.json"],
    "the bundle carries exactly manifest.json, icon.png, README.md"
  );

  const manifestInZip = JSON.parse(entries.get("manifest.json").toString("utf8"));
  assert.equal(manifestInZip.version, PKG.version, "manifest version is injected from package.json");
  assert.deepEqual(validateAgainstSchema(manifestInZip, SCHEMA), [], "manifest inside the zip validates too");

  assert.ok(
    entries.get("icon.png").subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
    "icon.png carries the PNG signature"
  );

  const readme = entries.get("README.md").toString("utf8");
  const agents = readFileSync(join(ROOT, "docs", "AGENTS.md"), "utf8");
  const claudeSection = agents.split(/^## /m).find((s) => s.startsWith("Claude Code (plugin)"));
  assert.ok(claudeSection, "docs/AGENTS.md has a Claude Code (plugin) section to source from");
  for (const line of claudeSection.split(/\r?\n/).filter((l) => l.trim().length > 0)) {
    assert.ok(readme.includes(line.trim()), `README.md carries Claude-section line: ${line.trim().slice(0, 60)}`);
  }
  assert.ok(readme.includes(`mcp-remote@${KIT.mcpRemote.pin}`), "README quotes the pinned bridge");
});

test("output stays out of git: dist/ is git-ignored", () => {
  const ignore = readFileSync(join(ROOT, ".gitignore"), "utf8");
  assert.match(ignore, /^dist\/$/m, ".gitignore must ignore dist/ (the .mcpb artifact is local-only)");
});

test("cleanup", { concurrency: false }, () => {
  rmSync(TMP, { recursive: true, force: true });
});
