#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// check-agent-kit.mjs — HELM-AGENT-KIT-1 gate. Regenerates every agent-kit
// artifact plus docs/AGENTS.md via scripts/gen-agent-kit.mjs and
// byte-compares each against the committed tree, then validates:
//   - SKILL.md frontmatter field-list (name/description/license/metadata)
//   - claude-plugin/plugin.json against the vendored unofficial schema
//     (hub/vendored/claude-plugin-schema/claude-plugin.schema.json)
//   - every verb referenced in SKILL.md exists in `bin/helmd.mjs --help`
//   - agent-kit/goose-deeplink.txt decodes and targets the loopback route
// Exit 0 green / exit 1 with the offending artifact named.

import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import { validate } from "./lib/schema-validator.mjs";
import { generate, parseGooseDeeplink } from "./gen-agent-kit.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

function check(root) {
  const issues = [];

  const committed = generate(root);
  for (const [rel, body] of committed) {
    const abs = rel === "docs/AGENTS.md" ? join(root, rel) : join(root, "agent-kit", rel);
    if (!existsSync(abs)) {
      issues.push(`stale agent kit: ${rel} is emitted but missing on disk`);
      continue;
    }
    const onDisk = readFileSync(abs, rel.endsWith(".zip") ? null : "utf8");
    if (!Buffer.isBuffer(body) && onDisk !== body) {
      issues.push(`byte drift: ${rel} differs from regeneration (stale emitted file or edited by hand)`);
    }
  }

  const skillAbs = join(root, "agent-kit", "skill", "SKILL.md");
  if (existsSync(skillAbs)) {
    const skill = readFileSync(skillAbs, "utf8");
    const fm = skill.match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (!fm) {
      issues.push("skill/SKILL.md: no frontmatter block");
    } else {
      const fields = fm[1];
      const required = ["name: helm-evidence", "license: Apache-2.0", "bins:", "helmd", "description:"];
      for (const want of required) {
        if (!fields.includes(want)) issues.push(`skill/SKILL.md frontmatter: missing "${want}"`);
      }
    }
  } else {
    issues.push("agent-kit/skill/SKILL.md missing");
  }

  const schemaPath = join(root, "hub", "vendored", "claude-plugin-schema", "claude-plugin.schema.json");
  const pluginPath = join(root, "agent-kit", "claude-plugin", "plugin.json");
  if (existsSync(schemaPath) && existsSync(pluginPath)) {
    const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
    const plugin = JSON.parse(readFileSync(pluginPath, "utf8"));
    const errs = validate(schema, plugin);
    if (errs.length > 0) {
      issues.push(`claude-plugin/plugin.json fails vendored schema:`, ...errs.slice(0, 8));
    }
  } else {
    issues.push("vendored schema or claude-plugin/plugin.json missing");
  }

  const helpText = sh(process.execPath, ["bin/helmd.mjs", "--help"], root);
  const verbs = new Set(
    helpText
      .split(/\r?\n/)
      .filter((l) => /^  [a-z][a-z0-9-]+( |$|\[)/.test(l))
      .map((l) => l.trim().split(/[\s<]+/)[0])
  );
  const skillText = readFileSync(skillAbs, "utf8");
  const used = new Set();
  for (const m of skillText.matchAll(/helmd ([a-z][a-z0-9-]+)/g)) used.add(m[1]);
  for (const v of used) {
    if (!verbs.has(v)) issues.push(`SKILL.md references verb "helmd ${v}" which is absent from bin/helmd.mjs --help`);
  }

  const deeplinkAbs = join(root, "agent-kit", "goose-deeplink.txt");
  if (existsSync(deeplinkAbs)) {
    try {
      parseGooseDeeplink(readFileSync(deeplinkAbs, "utf8"));
    } catch (e) {
      issues.push(`goose-deeplink.txt does not decode: ${e.message}`);
    }
  } else {
    issues.push("agent-kit/goose-deeplink.txt missing");
  }

  return issues;
}

function sh(cmd, args, cwd) {
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  return execFileSync(cmd, args, { cwd, env, stdio: ["ignore", "pipe", "inherit"] }).toString();
}

function main() {
  const issues = check(ROOT);
  if (issues.length > 0) {
    console.error("check-agent-kit: RED");
    for (const i of issues) console.error(i);
    process.exit(1);
  }
  console.log(`check-agent-kit: OK (14 artifacts, byte-compare + frontmatter + vendored schema + verb + deeplink checks green)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}

export { check };
