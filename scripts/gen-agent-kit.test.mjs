// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-AGENT-KIT-1 unit coverage: help/mcp parsers, deeplink decode, and the
// deterministic zip builder (two runs byte-identical). Reads the REAL sources
// (bin/helmd.mjs --help, hub/mcp.mjs) so a drift in either fails this file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseCliFromHelp, parseMcpToolsFromHub, parseGooseDeeplink, buildZip, generate } from "./gen-agent-kit.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const HELP = execFileSync(process.execPath, [join(ROOT, "bin", "helmd.mjs"), "--help"], { encoding: "utf8" });

test("parseCliFromHelp: exit contracts come from help text, not retyped", () => {
  const cli = parseCliFromHelp(HELP);
  for (const row of cli) {
    if (row.verb === "check") {
      assert.deepEqual(row.exitCodes, [
        "0 match",
        "1 differs",
        "2 no asserted value (recompute-only)",
        "3 insufficient input",
        "4 usage error",
        "5 scope disagreement",
      ]);
    }
    if (row.verb === "verify") {
      assert.deepEqual(row.exitCodes, ["0 valid", "1 invalid", "2 usage error (verification never attempted)"]);
    }
  }
  assert.ok(cli.length >= 16);
});

test("parseMcpToolsFromHub: exactly eight tools, parsed from the TOOLS literal", () => {
  const names = parseMcpToolsFromHub(readFileSync(join(ROOT, "hub", "mcp.mjs"), "utf8"));
  assert.equal(names.length, 8);
  assert.ok(names.includes("catalog.search"));
  assert.ok(names.includes("evidence.export"));
  assert.equal(names.filter((n) => n === "workflow.run").length, 1);
});

test("goose deeplink: decodes and rejects drift", () => {
  const generated = generate(ROOT);
  const parsed = parseGooseDeeplink(generated.get("goose-deeplink.txt"));
  assert.equal(parsed.cmd, "npx");
  assert.ok(parsed.args.some((a) => a.startsWith("mcp-remote@")));
  assert.throws(() => parseGooseDeeplink("goose cat foo"), /deeplink/i);
  assert.throws(() => parseGooseDeeplink("goose mcp://add?cmd=deno&arg=x"), /cmd must be npx/);
});

test("buildZip: two runs byte-identical (no clock, no compression)", () => {
  const a = buildZip([["SKILL.md", "hi\n"]]);
  const b = buildZip([["SKILL.md", "hi\n"]]);
  assert.equal(a.length, b.length);
  assert.ok(a.equals(b));
});
