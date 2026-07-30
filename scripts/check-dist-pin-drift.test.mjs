import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { collectPins, diffPins, platformTag, distBinaryPath } from "./check-dist-pin-drift.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const SCRIPT = join(HERE, "check-dist-pin-drift.mjs");

function writePack(dir, name, nodes) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, name), JSON.stringify({ manifest: { nodes } }));
}

test("check-dist-pin-drift: collectPins reads kernel_id/kernel_digest pairs out of packs/*.json", () => {
  const tmp = mkdtempSync(join(tmpdir(), "helm-bingate-unit-"));
  writePack(tmp, "pack-a.json", [
    { node_id: "n1", kernel_id: "art-78-csdr-penalty-calculator", kernel_digest: "sha256:aaaa" },
    { node_id: "n2", kernel_id: "art-84-settlement-efficiency-kpi", kernel_digest: "sha256:bbbb" },
  ]);
  writePack(tmp, "INDEX.json", []); // must be ignored, not a pack
  const pins = collectPins(tmp);
  assert.equal(pins.size, 2);
  assert.equal(pins.get("pack-a.json::art-78-csdr-penalty-calculator"), "sha256:aaaa");
  rmSync(tmp, { recursive: true, force: true });
});

test("check-dist-pin-drift: diffPins is silent when a binary's pins match the tree (constructed, not built)", () => {
  const tree = new Map([["pack-a.json::art-78", "sha256:696b4634"]]);
  const binMatching = new Map([["pack-a.json::art-78", "sha256:696b4634"]]);
  assert.deepEqual(diffPins(tree, binMatching), []);
});

test("check-dist-pin-drift: diffPins flags a real measured true positive (tree 696b4634 vs binary 1a1ae5b7)", () => {
  const tree = new Map([["pack-settlement-discipline-penalty.json::art-78-csdr-penalty-calculator", "sha256:696b46349d69a4f615727264f5a7a59492a6dfc1eb9b73e631af142a6d436a80"]]);
  const binStale = new Map([["pack-settlement-discipline-penalty.json::art-78-csdr-penalty-calculator", "sha256:1a1ae5b7775cad6c3619104c909084bd1b203d852325759671f8a6ad7e46a80"]]);
  const mismatches = diffPins(tree, binStale);
  assert.equal(mismatches.length, 1);
  assert.equal(mismatches[0].tree, "sha256:696b46349d69a4f615727264f5a7a59492a6dfc1eb9b73e631af142a6d436a80");
  assert.equal(mismatches[0].binary, "sha256:1a1ae5b7775cad6c3619104c909084bd1b203d852325759671f8a6ad7e46a80");
});

test("check-dist-pin-drift: diffPins does not flag a pin the binary predates (new kernel, not stale)", () => {
  const tree = new Map([
    ["pack-a.json::art-78", "sha256:aaaa"],
    ["pack-a.json::art-492-new", "sha256:cccc"],
  ]);
  const binOlder = new Map([["pack-a.json::art-78", "sha256:aaaa"]]);
  assert.deepEqual(diffPins(tree, binOlder), []);
});

test("check-dist-pin-drift: SKIPs (exit 0, no crash) when dist/ has no binary for this host platform", () => {
  const emptyDist = mkdtempSync(join(tmpdir(), "helm-bingate-empty-dist-"));
  const out = execFileSync(process.execPath, [SCRIPT], {
    encoding: "utf8",
    env: { ...process.env, HELM_DIST_DIR: emptyDist },
  });
  assert.match(out, /SKIP/);
  assert.ok(!existsSync(join(emptyDist, platformTag())));
  rmSync(emptyDist, { recursive: true, force: true });
});

test("check-dist-pin-drift: distBinaryPath names the host-matching platform dir + binary", () => {
  const p = distBinaryPath("/some/dist");
  assert.ok(p.includes(platformTag()));
  assert.ok(p.endsWith("helmd.exe") || p.endsWith("helmd"));
});
