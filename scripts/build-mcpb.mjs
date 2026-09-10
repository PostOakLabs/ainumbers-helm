#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// build-mcpb.mjs — HELM-MCPB-1. Packs packaging/mcpb/manifest.json into a
// Claude Desktop / Cowork one-click bundle at dist/helm-<version>.mcpb.
//
// Contract (spec HELM-MAINTENANCE-BUILD-SPEC.md §3.5):
//   - the bundle is a zip with store-only entries (no compression), sorted
//     by name, and a fixed DOS mtime — two builds of the same tree are
//     byte-identical, so the artifact is reproducible without signing keys;
//   - contents are exactly manifest.json, icon.png, README.md;
//   - the manifest is validated against the VENDORED mcpb manifest schema
//     (hub/vendored/mcpb-schema/, see VENDORED.md) before anything is
//     written — a manifest that does not validate never reaches dist/;
//   - zero npm dependencies: Node builtins only. @anthropic-ai/mcpb's
//     validate/sign CLI is a maintainer-side convenience, never a build
//     dependency of this script (see docs/INSTALL.md).
//
// The mcp-remote pin in the manifest is cross-checked against
// agent-kit/kit.json (mcpRemote.pin) — the agent kit is the single source
// of truth for the pin; the manifest is never allowed to drift from it.
//
// Structural decisions recorded in packaging/mcpb/PINS.md:
//   - server.entry_point is the schema-mandated required field; the bundle
//     deliberately ships no server file (the bridge is npx-fetched
//     mcp-remote — "no hand-written shim"), so it carries the value "npx".
//     Hosts launch via server.mcp_config.command/args and never execute
//     entry_point when mcp_config is present.
//   - icon.png is generated here, deterministically (the repo ships no
//     image asset to reuse; a stored-deflate PNG needs no zlib and is
//     byte-stable across machines).
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

// Fixed DOS timestamp for every zip entry: 2000-01-01 00:00:00 local.
const DOS_TIME = 0x0000;
const DOS_DATE = 0x2821; // ((2000 - 1980) << 9) | (1 << 5) | 1

// ---------------------------------------------------------------------------
// Minimal JSON Schema (draft-07) validator — the subset the vendored MCPB
// manifest schema actually uses, plus enough of the combinator vocabulary
// (anyOf/oneOf/allOf/$ref) to walk it faithfully. `format` is deliberately
// not asserted: in draft-07 it is an annotation by default, and asserting
// it would need a second hand-rolled grammar to drift out of date.
// Zero npm deps — node builtins only.
// ---------------------------------------------------------------------------
export function validateAgainstSchema(value, schema, root = schema, path = "$", errs = []) {
  if (schema.$ref !== undefined) {
    const target = resolveRef(schema.$ref, root);
    if (target === undefined) {
      errs.push(`${path}: unresolved $ref ${schema.$ref}`);
      return errs;
    }
    return validateAgainstSchema(value, target, root, path, errs);
  }
  if (schema.allOf) {
    for (const sub of schema.allOf) validateAgainstSchema(value, sub, root, path, errs);
  }
  if (schema.anyOf) {
    const branchErrs = schema.anyOf.map((s) => validateAgainstSchema(value, s, root, path, []));
    if (!branchErrs.some((e) => e.length === 0)) {
      errs.push(`${path}: matched none of ${schema.anyOf.length} anyOf branches`);
    }
  }
  if (schema.oneOf) {
    const passing = schema.oneOf.filter((s) => validateAgainstSchema(value, s, root, path, []).length === 0).length;
    if (passing !== 1) errs.push(`${path}: matched ${passing} of ${schema.oneOf.length} oneOf branches (need exactly 1)`);
  }
  if (schema.const !== undefined && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    errs.push(`${path}: expected const ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.some((v) => JSON.stringify(v) === JSON.stringify(value))) {
    errs.push(`${path}: ${JSON.stringify(value)} not in enum [${schema.enum.join(", ")}]`);
  }
  if (schema.type && !typeOk(schema.type, value)) {
    errs.push(`${path}: expected type ${schema.type}, got ${jsType(value)}`);
    return errs; // further checks assume the type
  }
  if (typeof value === "string") {
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) {
      errs.push(`${path}: ${JSON.stringify(trunc(value))} does not match /${schema.pattern}/`);
    }
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errs.push(`${path}: shorter than minLength ${schema.minLength}`);
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) errs.push(`${path}: less than minimum ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errs.push(`${path}: greater than maximum ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errs.push(`${path}: fewer than minItems ${schema.minItems}`);
    }
    if (schema.items) value.forEach((v, i) => validateAgainstSchema(v, schema.items, root, `${path}[${i}]`, errs));
  }
  if (isObj(value)) {
    for (const key of schema.required || []) {
      if (!(key in value)) errs.push(`${path}: missing required "${key}"`);
    }
    if (schema.properties) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (key in value) validateAgainstSchema(value[key], sub, root, `${path}.${key}`, errs);
      }
    }
    if (schema.additionalProperties !== undefined && isObj(schema.additionalProperties)) {
      // additionalProperties as a SCHEMA (not the boolean strict flag) — the
      // MCPB schema uses this for user_config and platform_overrides maps.
      const sub = schema.additionalProperties;
      for (const [key, v] of Object.entries(value)) {
        if (schema.properties && key in schema.properties) continue;
        validateAgainstSchema(v, sub, root, `${path}.${key}`, errs);
      }
    } else if (schema.additionalProperties === false && schema.properties) {
      const allowed = new Set(Object.keys(schema.properties));
      for (const key of Object.keys(value)) {
        if (!allowed.has(key)) errs.push(`${path}: additional property "${key}" not allowed (strict)`);
      }
    }
  }
  return errs;
}

function resolveRef(ref, root) {
  if (!ref.startsWith("#/")) return undefined;
  return ref
    .slice(2)
    .split("/")
    .map((seg) => seg.replace(/~1/g, "/").replace(/~0/g, "~"))
    .reduce((o, seg) => (o === undefined || o === null ? undefined : o[seg]), root);
}
function typeOk(t, v) {
  if (Array.isArray(t)) return t.some((x) => typeOk(x, v));
  return t === "object" ? isObj(v)
    : t === "null" ? v === null
    : t === "array" ? Array.isArray(v)
    : t === "string" ? typeof v === "string"
    : t === "number" ? typeof v === "number" && !Number.isNaN(v)
    : t === "integer" ? Number.isInteger(v)
    : t === "boolean" ? typeof v === "boolean"
    : true;
}
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const jsType = (v) => (Array.isArray(v) ? "array" : v === null ? "null" : typeof v);
const trunc = (s) => (s.length > 50 ? s.slice(0, 47) + "..." : s);

// ---------------------------------------------------------------------------
// Deterministic primitives: CRC-32 (zip) and Adler-32 (PNG IDAT) — computed
// bitwise, no tables, no engine variance.
// ---------------------------------------------------------------------------
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function adler32(buf) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

// ---------------------------------------------------------------------------
// icon.png — deterministic 64x64 RGBA PNG (deep-water blue with an amber
// helm-block inset), built with a STORED deflate block so no compressor is
// involved and the bytes are stable on every machine, forever.
// ---------------------------------------------------------------------------
export function makeIconPng() {
  const W = 64;
  const H = 64;
  const BG = [0x0b, 0x3b, 0x5c, 0xff]; // #0B3B5C
  const FG = [0xf0, 0xb2, 0x32, 0xff]; // #F0B232, centered 32x32
  const raw = Buffer.alloc(H * (1 + W * 4));
  for (let y = 0; y < H; y++) {
    const rowStart = y * (1 + W * 4);
    raw[rowStart] = 0; // filter type 0 (None)
    for (let x = 0; x < W; x++) {
      const px = rowStart + 1 + x * 4;
      const inset = x >= 16 && x < 48 && y >= 16 && y < 48;
      const color = inset ? FG : BG;
      raw[px] = color[0];
      raw[px + 1] = color[1];
      raw[px + 2] = color[2];
      raw[px + 3] = color[3];
    }
  }

  // One STORED (uncompressed) deflate block: bfinal=1, btype=00.
  const idat = Buffer.alloc(5 + raw.length + 4);
  idat[0] = 0x01;
  idat.writeUInt16LE(raw.length & 0xffff, 1);
  idat.writeUInt16LE(~raw.length & 0xffff, 3);
  raw.copy(idat, 5);
  idat.writeUInt32BE(adler32(raw), 5 + raw.length);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0);
  ihdr.writeUInt32BE(H, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", idat),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function pngChunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, "ascii");
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

// ---------------------------------------------------------------------------
// README.md — generated from docs/AGENTS.md (the generated agent kit doc),
// never hand-written here: the Claude section plus the security posture.
// ---------------------------------------------------------------------------
export function extractSection(markdown, heading) {
  const lines = markdown.split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === `## ${heading}`);
  if (start === -1) throw new Error(`docs/AGENTS.md: no "## ${heading}" section found`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^## /.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n").trim();
}

function makeReadme(root) {
  const agents = readFileSync(join(root, "docs", "AGENTS.md"), "utf8");
  const kit = JSON.parse(readFileSync(join(root, "agent-kit", "kit.json"), "utf8"));
  const pin = kit.mcpRemote.pin;
  const claude = extractSection(agents, "Claude Code (plugin)");
  const posture = extractSection(agents, "Security posture");
  return [
    "# Helm — Claude Desktop / Cowork bridge",
    "",
    `Generated by \`scripts/build-mcpb.mjs\` from the repo's generated agent docs — do not edit inside the bundle. This bundle does not contain a Helm server: it bridges the host to an already-installed, already-running \`helmd\` daemon over its loopback MCP endpoint (\`${kit.daemon.url}/mcp\`), using the pinned \`mcp-remote@${pin}\` as the stdio-to-loopback bridge, run by the host itself.`,
    "",
    "Paste a pairing token (printed by `helmd open` / first run) when the host asks for it. The daemon stays loopback-only; the bridge adds the `Origin` header the daemon requires.",
    "",
    "## Claude Code (plugin)",
    "",
    claude.replace(/^## Claude Code \(plugin\)\s*/, "").trim(),
    "",
    "## Security posture",
    "",
    posture.replace(/^## Security posture\s*/, "").trim(),
    "",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Structural checks beyond the JSON Schema — the §3.5 contract, enforced
// mechanically against the single-source-of-truth inputs (kit.json pin).
// ---------------------------------------------------------------------------
function structuralChecks(manifest, kit) {
  const issues = [];
  const pin = kit.mcpRemote.pin;
  const wantArgs = [
    "-y",
    `mcp-remote@${pin}`,
    "http://127.0.0.1:${user_config.port}/mcp",
    "--header",
    "Authorization: Bearer ${user_config.token}",
    "--header",
    "Origin: http://127.0.0.1:${user_config.port}",
  ];
  if (manifest.server?.type !== "node") issues.push(`server.type must be "node"`);
  if (manifest.server?.mcp_config?.command !== "npx") issues.push(`server.mcp_config.command must be "npx"`);
  const gotArgs = manifest.server?.mcp_config?.args;
  if (JSON.stringify(gotArgs) !== JSON.stringify(wantArgs)) {
    issues.push(`server.mcp_config.args drift from the §3.5 bridge contract (mcp-remote@${pin} + Bearer/Origin headers)`);
  }
  const token = manifest.user_config?.token;
  if (token?.sensitive !== true) issues.push("user_config.token.sensitive must be true");
  if (token?.required !== true) issues.push("user_config.token.required must be true");
  if (manifest.user_config?.port?.default !== 4173) issues.push("user_config.port.default must be 4173");
  if (manifest.manifest_version !== "0.3") issues.push(`manifest_version must be "0.3"`);
  return issues;
}

// ---------------------------------------------------------------------------
// Deterministic store-only zip.
// ---------------------------------------------------------------------------
export function buildZip(entries) {
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const nameBufs = sorted.map((e) => Buffer.from(e.name, "utf8"));
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (let i = 0; i < sorted.length; i++) {
    const { data } = sorted[i];
    const crc = crc32(data);
    const local = Buffer.alloc(30 + nameBufs[i].length);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // method: store
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed (= stored)
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBufs[i].length, 26);
    local.writeUInt16LE(0, 28); // extra len
    nameBufs[i].copy(local, 30);
    locals.push(local, data);

    const central = Buffer.alloc(46 + nameBufs[i].length);
    central.writeUInt32LE(0x02014b50, 0); // central directory signature
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8); // flags
    central.writeUInt16LE(0, 10); // method: store
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBufs[i].length, 28);
    central.writeUInt16LE(0, 30); // extra len
    central.writeUInt16LE(0, 32); // comment len
    central.writeUInt16LE(0, 34); // disk start
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE(0, 38); // external attrs
    central.writeUInt32LE(offset, 42); // local header offset
    nameBufs[i].copy(central, 46);
    centrals.push(central);

    offset += local.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4); // this disk
  eocd.writeUInt16LE(0, 6); // CD disk
  eocd.writeUInt16LE(sorted.length, 8);
  eocd.writeUInt16LE(sorted.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16); // CD offset
  eocd.writeUInt16LE(0, 20); // comment len
  return Buffer.concat([...locals, cd, eocd]);
}

// Parse a store-only zip built by buildZip back into {name, data} records —
// used by the row test to assert on the bundle's internals.
export function readZipEntries(bytes) {
  const eocd = bytes.readUInt32LE(bytes.length - 22) === 0x06054b50 ? bytes.length - 22 : -1;
  if (eocd === -1) throw new Error("not a zip this builder produced (no tail EOCD)");
  const count = bytes.readUInt16LE(eocd + 10);
  let off = bytes.readUInt32LE(eocd + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    if (bytes.readUInt32LE(off) !== 0x02014b50) throw new Error("bad central directory");
    const nameLen = bytes.readUInt16LE(off + 28);
    const localOffset = bytes.readUInt32LE(off + 42);
    const name = bytes.slice(off + 46, off + 46 + nameLen).toString("utf8");
    const localNameLen = bytes.readUInt16LE(localOffset + 26);
    const localExtraLen = bytes.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const size = bytes.readUInt32LE(off + 24);
    out.push({ name, data: bytes.slice(dataStart, dataStart + size) });
    off += 46 + nameLen + bytes.readUInt16LE(off + 30) + bytes.readUInt16LE(off + 32);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The build itself.
// ---------------------------------------------------------------------------
export function buildMcpb(root, outDir) {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  const sourceManifest = JSON.parse(readFileSync(join(root, "packaging", "mcpb", "manifest.json"), "utf8"));
  const kit = JSON.parse(readFileSync(join(root, "agent-kit", "kit.json"), "utf8"));
  const schema = JSON.parse(
    readFileSync(join(root, "hub", "vendored", "mcpb-schema", "mcpb-manifest-v0.3.schema.json"), "utf8")
  );

  // The manifest's version field is injected from package.json at build
  // time — one source of truth for the release version, never retyped.
  const manifest = structuredClone(sourceManifest);
  manifest.version = pkg.version;

  const schemaErrs = validateAgainstSchema(manifest, schema);
  if (schemaErrs.length > 0) {
    throw new Error(`packaging/mcpb/manifest.json fails the vendored MCPB schema:\n  ${schemaErrs.join("\n  ")}`);
  }
  const structuralErrs = structuralChecks(manifest, kit);
  if (structuralErrs.length > 0) {
    throw new Error(`packaging/mcpb/manifest.json fails the §3.5 structural contract:\n  ${structuralErrs.join("\n  ")}`);
  }

  const bytes = buildZip([
    { name: "manifest.json", data: Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf8") },
    { name: "icon.png", data: makeIconPng() },
    { name: "README.md", data: Buffer.from(makeReadme(root), "utf8") },
  ]);

  const name = `helm-${pkg.version}.mcpb`;
  const outPath = join(outDir, name);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(outPath, bytes);
  return { name, outPath, bytes };
}

function main() {
  const root = join(HERE, "..");
  const { outPath, bytes } = buildMcpb(root, join(root, "dist"));
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  console.log(`build-mcpb: wrote ${outPath}`);
  console.log(`build-mcpb: sha256 ${sha256} (${bytes.length} bytes, store-only, deterministic)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
