#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// gen-agent-kit.mjs — HELM-AGENT-KIT-1 emitter (spec HELM-MAINTENANCE-BUILD-SPEC.md §3.1).
// Hand-authored inputs: agent-kit/kit.json + agent-kit/skill/SKILL.md.
// Everything else is emitted. Two sources are PARSED at generation, never
// retyped:
//   - CLI verbs + exit codes: `node bin/helmd.mjs --help` output
//   - MCP tool names: the TOOLS array literal in hub/mcp.mjs
// docs/AGENTS.md and agent-kit/helm-skill.zip are also emitted here. The zip
// is deterministic: node builtins only, store-mode entries, fixed DOS epoch,
// stable entry order.
// scripts/check-agent-kit.mjs regenerates into a scratch tree and byte-compares
// every artifact below against the committed bytes.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const KIT_DIR = join(ROOT, "agent-kit");

function sh(cmd, args) {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  return execFileSync(cmd, args, { cwd: ROOT, env, stdio: ["ignore", "pipe", "inherit"] }).toString();
}

// ---------------------------------------------------------------------------
// Parsers (exported so scripts/gen-agent-kit.test.mjs can unit-test them)
// ---------------------------------------------------------------------------

export function parseCliFromHelp(helpText) {
  const lines = helpText.split(/\r?\n/);
  const start = lines.findIndex((l) => l.startsWith("Commands:"));
  const end = lines.findIndex((l) => l.startsWith("Options:"));
  if (start < 0 || end < 0) throw new Error("helmd --help: did not find the Commands:/Options: blocks");

  // Paragraphs: a line with a bare two-space indent whose first token is a
  // verb opens one (even when the same verb repeats for multi-form usage,
  // e.g. check); deeper indentation continues the current paragraph.
  const body = lines.slice(start + 1, end);
  const isLead = (l) => /^  [a-z][a-z0-9-]+( |$|\[)/.test(l);
  const paragraphs = [];
  let cur = null;
  for (const line of body) {
    if (isLead(line)) {
      cur = [line];
      paragraphs.push(cur);
    } else if (cur) {
      cur.push(line);
    }
  }
  const verbs = [];
  for (const p of paragraphs) {
    const verb = p[0].match(/^  ([a-z][a-z0-9-]+)/)[1];
    if (!verbs.includes(verb)) verbs.push(verb);
  }
  if (verbs.length === 0) throw new Error("helmd --help: parsed zero verbs");

  // A paragraph that names its own exit contract gets those codes ("Exit
  // codes: 0 match, 1 differs, ..." for check; "0 valid, 1 invalid, 2 usage
  // error (verification never attempted)." for verify). Every other verb
  // inherits the CLI-global footer: 0 success / 2 usage error.
  const declared = new Map();
  for (const p of paragraphs) {
    const verb = p[0].match(/^  ([a-z][a-z0-9-]+)/)[1];
    if (declared.has(verb)) continue;
    const text = p.join(" ").replace(/\s+/g, " ");
    const m = text.match(/Exit codes:\s*(.+?)\s*(?:\.|$)/s);
    if (!m) continue;
    const caught = m[1].split(/,\s*(?=\d)/);
    if (caught.length > 0) declared.set(verb, caught);
  }
  const footer = lines.slice(end).find((l) => l.includes("Exit codes:"));
  if (!footer) throw new Error("helmd --help: did not find the trailing Exit codes footer");
  return verbs.map((verb) => ({ verb, exitCodes: declared.get(verb) || ["0 success", "2 usage error"] }));
}

export function parseMcpToolsFromHub(mcpSource) {
  const block = mcpSource.match(/const TOOLS = \[([\s\S]*?)\n\];/);
  if (!block) throw new Error("hub/mcp.mjs: TOOLS array literal not found");
  const names = [];
  for (const m of block[1].matchAll(/\{\s*name:\s*"([^"]+)"/g)) names.push(m[1]);
  if (names.length !== 8) throw new Error(`hub/mcp.mjs: expected exactly 8 tools, parsed ${names.length}`);
  return names;
}

// ---------------------------------------------------------------------------
// Deterministic zip (store mode, node builtins only)
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// 1980-01-01 00:00:00 (the ZIP epoch minimum) as little-endian halves.
const DOS_EPOCH_LO = 0x0000; // time  HH:MM:SS -> 00:00:00
const DOS_EPOCH_HI = 0x0021; // date  YYYYYYYM MMMDDDDD -> 1980-01-01

export function buildZip(entries) {
  const parts = [];
  const central = [];
  let offset = 0;
  for (const [name, body] of entries) {
    const nameBuf = Buffer.from(name, "utf8");
    const data = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30 + nameBuf.length + data.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(DOS_EPOCH_LO, 10);
    local.writeUInt16LE(DOS_EPOCH_HI, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);
    nameBuf.copy(local, 30);
    data.copy(local, 30 + nameBuf.length);
    parts.push(local);
    const cen = Buffer.alloc(46 + nameBuf.length);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(0, 8);
    cen.writeUInt16LE(0, 10);
    cen.writeUInt16LE(DOS_EPOCH_LO, 12);
    cen.writeUInt16LE(DOS_EPOCH_HI, 14);
    cen.writeUInt32LE(crc, 16);
    cen.writeUInt32LE(data.length, 20);
    cen.writeUInt32LE(data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    for (const at of [30, 32, 36, 38]) cen.writeUInt16LE(0, at);
    cen.writeUInt32LE(offset, 42);
    nameBuf.copy(cen, 46);
    central.push(cen);
    offset += local.length;
  }
  const cenStart = offset;
  parts.push(...central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.reduce((n, c) => n + c.length, 0), 12);
  eocd.writeUInt32LE(cenStart, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...parts, eocd]);
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

function j(o) {
  return JSON.stringify(o, null, 2) + "\n";
}

function remoteArgs(pin, url) {
  return [
    "mcp-remote@" + pin,
    url + "/mcp",
    "--header",
    "Authorization: Bearer ${HELM_TOKEN}",
    "--header",
    "Origin: " + url,
  ];
}

const DEFAULT_TOOL_FILTER = ["workflow.run", "evidence.export"];

export function parseGooseDeeplink(text) {
  const line = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)[0];
  if (!line) throw new Error("goose-deeplink.txt is empty");
  const m = line.match(/^goose\s+mcp:\/\/add\?(\S+)$/);
  if (!m) throw new Error(`goose-deeplink.txt is not a goose mcp add deeplink: ${line}`);
  const q = new URLSearchParams(m[1]);
  if (q.get("cmd") !== "npx") throw new Error(`deeplink cmd must be npx, got ${q.get("cmd")}`);
  const args = [...q.getAll("arg")];
  if (!args.some((a) => a.startsWith("mcp-remote@"))) throw new Error("deeplink must pin an mcp-remote version");
  if (!args.includes("Origin:http://127.0.0.1:4173")) throw new Error("deeplink must carry the Origin header workaround");
  if (!args.includes("http://127.0.0.1:4173/mcp")) throw new Error("deeplink must target the loopback /mcp route");
  if (!args.some((a) => a.startsWith("Authorization:Bearer "))) throw new Error("deeplink must carry the bearer header");
  return { cmd: q.get("cmd"), args };
}

export function emitters(kit, cli, tools, skillBody) {
  const pin = kit.mcpRemote.pin;
  const url = kit.daemon.url || `http://127.0.0.1:${kit.daemon.defaultPort}`;
  const out = new Map();
  const set = (rel, body) => out.set(rel, body);

  set(
    "kit.json",
    j({
      kitVersion: 1,
      // Every static kit field is passed through from the input file; cli +
      // mcpTools (and daemon.url) are parsed/derived at generation only.
      version: kit.version,
      repository: kit.repository,
      installDir: kit.installDir,
      daemon: {
        url,
        defaultPort: kit.daemon.defaultPort,
        tokenLocation: kit.daemon.tokenLocation,
      },
      mcp: {
        path: "/mcp",
        transport: "streamable-http",
        headers: { Authorization: "Bearer ${HELM_TOKEN}", Origin: url },
        toolFilter: { exclude: DEFAULT_TOOL_FILTER },
      },
      cli: { helpSource: "bin/helmd.mjs --help", verbs: cli },
      mcpTools: { source: "hub/mcp.mjs TOOLS", names: tools },
      mcpRemote: kit.mcpRemote,
    })
  );

  set("skill/SKILL.md", skillBody);

  set(
    "openclaw/mcp-servers.fragment.json",
    j({
      mcpServers: {
        helm: {
          url: url + "/mcp",
          transport: "streamable-http",
          headers: { Authorization: "Bearer ${HELM_TOKEN}", Origin: url },
          toolFilter: { exclude: DEFAULT_TOOL_FILTER },
        },
      },
    })
  );

  set(
    "openclaw/exec-allowlist.fragment.json",
    j({
      exec: {
        allow: ["helmd check", "helmd verify", "helmd status --json", "helmd list-scenarios"],
        safeBins: ["helmd"],
        safeBinTrustedDirs: [kit.installDir],
      },
    })
  );

  set(
    "openclaw/cron.fragment.json",
    j({
      automations: [
        {
          name: "helm-nightly-check",
          schedule: "0 0 * * *",
          commands: [`helmd check <pack_id> --glob "extracts/*.json" --json`],
        },
        {
          name: "helm-heartbeat",
          schedule: "0 4,12,20 * * *",
          commands: ["helmd status --json"],
        },
      ],
    })
  );

  set(
    "claude-plugin/plugin.json",
    j({
      name: "helm-evidence",
      version: kit.version,
      description: "Local-first AI-number figures via helmd and its loopback MCP server. Offline check, verify, and scenario listing; no knowledge of anything outside this repo.",
      author: { name: "Post Oak Labs, Inc." },
      repository: kit.repository,
      license: "Apache-2.0",
      keywords: ["helm", "evidence", "mcp", "verification"],
      mcpServers: {
        helm: {
          command: "npx",
          args: remoteArgs(pin, url),
        },
      },
    })
  );

  set("claude-plugin/skills/helm-evidence/SKILL.md", skillBody);

  set(
    "gemini/gemini-extension.json",
    j({
      name: "helm-evidence",
      version: kit.version,
      mcpServers: {
        helm: {
          httpUrl: url + "/mcp",
          headers: { Authorization: "Bearer ${HELM_TOKEN}", Origin: url },
        },
      },
    })
  );

  set(
    "goose-deeplink.txt",
    `goose mcp://add?cmd=npx&arg=mcp-remote@${pin}&arg=${url}/mcp&arg=--header&arg=${encodeURIComponent("Authorization:Bearer ${HELM_TOKEN}")}&arg=--header&arg=Origin:${url}\n`
  );

  set("cursor.mcp.json", j({ mcpServers: { helm: { command: "npx", args: remoteArgs(pin, url) } } }));
  set("vscode.mcp.json", j({ servers: { helm: { command: "npx", args: remoteArgs(pin, url) } } }));
  set("hermes.mcp.json", j({ mcpServers: { helm: { command: "npx", args: remoteArgs(pin, url) } } }));
  set("helm-skill.zip", buildZip([["SKILL.md", skillBody]]));

  return out;
}

// ---------------------------------------------------------------------------
// docs/AGENTS.md (generated)
// ---------------------------------------------------------------------------

const DOC_REQUIRED_MARKS = [
  "OpenClaw",
  "AutoClaw",
  "n8n",
  "Canvas",
  "hardened-fork",
  "openclaw mcp probe",
  "security posture",
];

export function missingDocMarks(doc) {
  return DOC_REQUIRED_MARKS.filter((mark) => !doc.includes(mark));
}

function stripFenceDump(fragment) {
  return fragment.trim();
}

export function buildDocsAgentsMd({ kit, cli, tools, fragments }) {
  const pin = kit.mcpRemote.pin;
  const url = kit.daemon.url;
  const readRows = cli
    .filter((v) => ["check", "verify", "status", "list-scenarios"].includes(v.verb))
    .map((v) => `- \`helmd ${v.verb}\`: exit codes ${v.exitCodes.join(", ")}.`)
    .join("\n");
  return `# Helm for agents

Generated by \`scripts/gen-agent-kit.mjs\` from \`agent-kit/kit.json\`; do not
edit by hand. Everything under \`agent-kit/\` is emitted, so a new host becomes
a new emitter, never a new daemon feature. Gate in CI:
\`node scripts/check-agent-kit.mjs\` regenerates every file and byte-compares
it against the committed tree.

Agents talk to the loopback daemon at ${url} (default port
${kit.daemon.defaultPort}, bearer token under \`${kit.daemon.tokenLocation}\`),
over the MCP Streamable HTTP transport at \`/mcp\`. The
${tools.length} MCP tools are parsed from \`hub/mcp.mjs\`; CLI verbs are
parsed from \`bin/helmd.mjs --help\`. The \`Origin\` header workaround below
exists precisely so users get a paste-able \`mcp.servers\` entry without a
\`hub/\` change in this same row.

## OpenClaw

Paste the \`mcpServers\` block from
\`agent-kit/openclaw/mcp-servers.fragment.json\` into \`openclaw.json\`. It
carries the \`Origin: ${url}\` header plus
\`\${HELM_TOKEN}\` interpolation for the bearer token:

\`\`\`json
${stripFenceDump(fragments["openclaw/mcp-servers.fragment.json"])}
\`\`\`

Exec allowlist (\`agent-kit/openclaw/exec-allowlist.fragment.json\`): allow
\`helmd check\`, \`helmd verify\`, \`helmd status --json\`, and
\`helmd list-scenarios\`. Never put \`node\` or a shell on the allow list:
\`helmd\` is the only safe bin, and \`safeBinTrustedDirs\` points at the
install dir (\`${kit.installDir}\`).

Cron and heartbeat live in \`agent-kit/openclaw/cron.fragment.json\`: a
nightly \`helmd check\` over \`extracts/*.json\`, plus a heartbeat
\`helmd status --json\`.

OpenClaw does not run natively on Windows: use WSL 2, Docker (WSL backend), or
the standalone binary.

## AutoClaw

Import through the app's Skills UI: Plugins, Skills, import ZIP, then pick
\`agent-kit/helm-skill.zip\`. The zip is deterministic and built from the
same \`SKILL.md\`. If fragments need tuning for a pinned OpenClaw version,
edit \`agent-kit/kit.json\` + the emitters and regenerate; do not patch the
fragments in place.

## n8n

n8n's MCP Client node speaks the same Streamable HTTP transport. Same box as
OpenClaw: URL ${url}/mcp, header Authorization set to Bearer +
\`\${HELM_TOKEN}\` (via an n8n credential), and header Origin set to
${url} or helmd answers 403 \`origin_mismatch\`. Keep the tool filter
excluding \`workflow.run\` and \`evidence.export\` there as well.

## Claude Code (plugin)

\`agent-kit/claude-plugin/plugin.json\` is the Claude Code plugin manifest
(\`.claude-plugin/plugin.json\` once the plugin is installed at a plugin
root). It carries an inline \`mcpServers\` block using
\`npx mcp-remote@${pin}\` plus the two headers, and references the skill at
\`claude-plugin/skills/helm-evidence/SKILL.md\`. In CI, that manifest is
validated against the vendored unofficial schema under
\`hub/vendored/claude-plugin-schema/\`.

## Gemini CLI

Copy \`agent-kit/gemini/gemini-extension.json\` into the extension directory
Gemini reads (context file and config live in the same directory). The
extension exposes the same read-only tool filter.

## Goose

\`agent-kit/goose-deeplink.txt\` is a paste-able \`mcp://add\` deeplink:
\`cmd=npx\`, a pinned \`mcp-remote@${pin}\`, the loopback URL, and the bearer
plus Origin headers. Decode the deeplink before pasting into a team channel.

## Cursor / VS Code / Hermes

\`agent-kit/cursor.mcp.json\`, \`agent-kit/vscode.mcp.json\`, and
\`agent-kit/hermes.mcp.json\` carry the respective shapes (command \`npx\`,
same \`mcp-remote@${pin}\` args). All of them keep the same two headers.

## NanoClaw / hardened-fork network note

Hardened forks and embedded runners (NanoClaw included) may not run
helmd-proxied MCP over loopback by default. The same rule holds for every
host in this kit: keep the daemon loopback-only and proxy through
\`mcp-remote\` (or an equivalent stack) rather than binding port 4173 to a
real interface. If a fork refuses \`mcp-remote\`, no manifest in this kit is
usable there: the bearer token plus the Origin header workaround is the
transport contract.

## Canvas

Give Canvas a scene-list node whose command points at the paired hub:
\`canvas.navigate\` to \`${url}/#token=<pairing>\`; keep
gateway.nodes.commands.allow tight to \`helmd\` shims. The node-command
allowlist recipe is UNVERIFIED-ON-MACOS: this build box is Windows, and the
row does not claim a macOS run. Record a macOS run before ever labelling this
recipe verified there.

## Smoke test

\`openclaw mcp probe\` plus \`mcp doctor --probe\` are the documented smoke
test. Probes should enumerate the 8 tools and show the filter pushing
\`workflow.run\` and \`evidence.export\` out of the reachable set. From the
daemon side, \`helmd doctor --json\` does the same checks.

## Security posture

Loopback stays: the daemon listens on 127.0.0.1 by default; do not bind a real
interface for agent convenience. Every agent client gets its own pairing
token; do not share one token across clients. The export tier is unreachable
from \`tools/call\` alone: \`evidence.export\` additionally needs a consent
ticket minted by the paired UI. The read-only default tool filter keeps
\`workflow.run\` and \`evidence.export\` excluded unless a human flips the
filter.

## CLI quick reference

Verb and exit-code rows below are parsed from \`bin/helmd.mjs --help\` at
generation (never retyped):

${readRows}

Without an asserted value, exit code 2 means recompute-only (still useful);
\`--no-anchor\` is the documented way to run check without anchoring. Quote
exit codes when citing results; never paste raw extract numbers into chat.
`;
}

// ---------------------------------------------------------------------------
// Generator driver: regenerate into a target ROOT (exported for check)
// ---------------------------------------------------------------------------

export function generate(root) {
  const kit = JSON.parse(readFileSync(join(root, "agent-kit", "kit.json"), "utf8"));
  const skillBody = readFileSync(join(root, "agent-kit", "skill", "SKILL.md"), "utf8");
  const cli = parseCliFromHelp(sh(process.execPath, ["bin/helmd.mjs", "--help"]));
  const tools = parseMcpToolsFromHub(readFileSync(join(root, "hub", "mcp.mjs"), "utf8"));
  const fragments = emitters(kit, cli, tools, skillBody);
  const docs = buildDocsAgentsMd({
    kit,
    cli,
    tools,
    fragments: Object.fromEntries(fragments),
  });
  fragments.set("docs/AGENTS.md", docs);
  return fragments;
}

function emit(root) {
  const files = generate(root);
  for (const [rel, body] of files) {
    // Everything is emitted under agent-kit/, except the doc that ships at docs/.
    const abs = rel === "docs/AGENTS.md" ? join(root, rel) : join(root, "agent-kit", rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, body);
    console.log(rel);
  }
  return files;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const files = emit(ROOT);
  const zip = files.get("helm-skill.zip");
  return { files: files.size, zipCrc: crc32(zip).toString(16) };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = main();
  console.log(`gen-agent-kit: emitted ${result.files} artifacts (helm-skill.zip crc32 ${result.zipCrc})`);
}
