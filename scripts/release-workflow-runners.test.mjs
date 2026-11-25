// Structural gate for .github/workflows/release.yml runner labels and the
// mcpb job's gate. Rides scripts/test.mjs (already CI-wired).
//
// Why: on 2026-11-24 the macos-arm64 build leg asked for `macos-14`, which
// GitHub no longer accepts ("The configuration 'macos-14-arm64-us-default'
// is not supported", run 45304701436). The leg was cancelled, the release
// was never created, and tag 2026.11.24 was left with no assets, which the
// scheduled release absence gate then reported. The mcpb job still ran and
// failed on "release not found", so the visible red pointed at the wrong job.
// Zero npm deps: regex checks over the YAML text, like the other workflow
// gates in this folder.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const text = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8");

// Hosted images GitHub has retired or stopped accepting for this repo.
// Add to this list when GitHub retires another one.
const RETIRED = ["macos-12", "macos-13", "macos-14", "ubuntu-20.04", "windows-2019"];

test("release.yml asks for no retired hosted runner image", () => {
  const labels = [
    ...[...text.matchAll(/^\s*-?\s*os:\s*(\S+)/gm)].map((m) => m[1]),
    ...[...text.matchAll(/^\s*runs-on:\s*(\S+)/gm)].map((m) => m[1]),
  ].map((l) => l.replace(/["']/g, ""));
  assert.ok(labels.length > 0, "no runner labels found");
  for (const l of labels) {
    assert.ok(!RETIRED.includes(l), `retired runner image in release.yml: ${l}`);
  }
});

test("release.yml still builds all four platform legs", () => {
  for (const tag of ["linux-x64", "windows-x64", "macos-x64", "macos-arm64"]) {
    assert.match(text, new RegExp(`tag:\\s*${tag}\\b`), `build matrix lost ${tag}`);
  }
});

test("mcpb job on a tag push waits for sign-and-release to succeed", () => {
  const start = text.indexOf("\n  mcpb:");
  assert.notEqual(start, -1, "mcpb job missing");
  const block = text.slice(start, start + 1500);
  const ifLine = block.match(/^\s*if:\s*(.+)$/m);
  assert.ok(ifLine, "mcpb job has no if:");
  assert.match(
    ifLine[1],
    /github\.event_name == 'push' && needs\.sign-and-release\.result == 'success'/,
    "mcpb must require sign-and-release success on a tag push",
  );
  assert.match(ifLine[1], /inputs\.tag != ''/, "mcpb must still run on a backfill dispatch with a tag");
});
