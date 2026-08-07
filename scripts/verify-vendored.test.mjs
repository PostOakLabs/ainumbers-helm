// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Local-only (no network) coverage for verify-vendored.mjs — the live upstream
// re-fetch path (collectUpstreamDriftIssues, inside runCLI) needs network and
// is exercised by the dedicated CI step instead (STANDING ORDERS: `npm test`
// must stay offline-runnable). This proves: (a) the real, shipped manifests
// pass today; (b) a manifest missing `license` or `pinnedSha` is caught, not
// silently accepted (HELM-VENDOR-LICENSE-1); (c) a tampered vendored byte is
// caught; (d) an unmanifested vendored tree is caught.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  collectConfigDrivenIssues,
  collectHeterogeneousIssues,
  collectUncoveredTreeIssues,
} from "./verify-vendored.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

function sha256Str(s) {
  return createHash("sha256").update(s).digest("hex");
}

test("verify-vendored: real hub/vendored/ocg tree passes local checks (license + pinnedSha present, bytes match)", () => {
  const config = JSON.parse(readFileSync(join(HERE, "vendor.config.json"), "utf8"));
  const issues = collectConfigDrivenIssues(join(ROOT, config.destination), config);
  assert.deepEqual(issues, []);
});

test("verify-vendored: real hub/vendored/anchor-suite tree passes local checks", () => {
  const config = JSON.parse(readFileSync(join(HERE, "vendor-anchor.config.json"), "utf8"));
  const issues = collectConfigDrivenIssues(join(ROOT, config.destination), config);
  assert.deepEqual(issues, []);
});

test("verify-vendored: real hub/vendored/ssh-sig tree passes local checks", () => {
  const config = JSON.parse(readFileSync(join(HERE, "vendor-ssh-sig.config.json"), "utf8"));
  const issues = collectConfigDrivenIssues(join(ROOT, config.destination), config);
  assert.deepEqual(issues, []);
});

test("verify-vendored: real ui/vendored tree passes local checks (every entry licensed + pinned, bytes match)", () => {
  const issues = collectHeterogeneousIssues(join(ROOT, "ui/vendored"), join(ROOT, "ui/vendored/MANIFEST.json"), "ui/vendored");
  assert.deepEqual(issues, []);
});

test("verify-vendored: real repo tree has no vendored root outside the known/covered set", () => {
  const issues = collectUncoveredTreeIssues(ROOT);
  assert.deepEqual(issues, []);
});

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "helm-verify-vendored-test-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("verify-vendored: config-driven manifest missing `license` is caught, not silently accepted", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "a.txt"), "hello");
    const fileHash = sha256Str("hello");
    writeFileSync(
      join(dir, "MANIFEST.json"),
      JSON.stringify({
        sourceRepo: "https://example.test/repo.git",
        pinnedSha: "deadbeef",
        vendoredPaths: ["a.txt"],
        fileCount: 1,
        files: [{ path: "a.txt", sha256: fileHash }],
      })
    );
    const config = { sourceRepo: "https://example.test/repo.git", pinnedSha: "deadbeef", paths: ["a.txt"], destination: "tmp" };
    const issues = collectConfigDrivenIssues(dir, config);
    assert.ok(issues.some((m) => /missing\/empty license/.test(m)), `expected a missing-license issue, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: config-driven manifest with a tampered byte is caught", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "a.txt"), "hello");
    const correctHash = sha256Str("hello");
    writeFileSync(
      join(dir, "MANIFEST.json"),
      JSON.stringify({
        sourceRepo: "https://example.test/repo.git",
        license: "MIT",
        pinnedSha: "deadbeef",
        vendoredPaths: ["a.txt"],
        fileCount: 1,
        files: [{ path: "a.txt", sha256: correctHash }],
      })
    );
    // Tamper the vendored byte after the manifest was written.
    writeFileSync(join(dir, "a.txt"), "tampered");
    const config = { sourceRepo: "https://example.test/repo.git", pinnedSha: "deadbeef", paths: ["a.txt"], destination: "tmp" };
    const issues = collectConfigDrivenIssues(dir, config);
    assert.ok(issues.some((m) => /hash mismatch/.test(m)), `expected a hash-mismatch issue, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: heterogeneous manifest entry missing pinnedSha/license is caught per-entry", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "b.txt"), "world");
    const fileHash = sha256Str("world");
    const manifestPath = join(dir, "MANIFEST.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        entries: [
          {
            classification: "third-party-vendor",
            sourceRepo: "https://example.test/upstream.git",
            // pinnedSha deliberately omitted
            // license deliberately omitted
            files: [{ path: "b.txt", sha256: fileHash }],
          },
        ],
      })
    );
    const issues = collectHeterogeneousIssues(dir, manifestPath, "tmp");
    assert.ok(issues.some((m) => /missing\/empty pinnedSha/.test(m)), `expected missing pinnedSha, got: ${JSON.stringify(issues)}`);
    assert.ok(issues.some((m) => /missing\/empty license/.test(m)), `expected missing license, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: heterogeneous manifest with an on-disk file not listed in any entry is caught", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "listed.txt"), "a");
    writeFileSync(join(dir, "orphan.txt"), "b");
    const listedHash = sha256Str("a");
    const manifestPath = join(dir, "MANIFEST.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        entries: [
          {
            classification: "first-party-own",
            sourceRepo: "https://example.test/repo.git",
            pinnedSha: "n/a",
            license: "Apache-2.0",
            files: [{ path: "listed.txt", sha256: listedHash }],
          },
        ],
      })
    );
    const issues = collectHeterogeneousIssues(dir, manifestPath, "tmp");
    assert.ok(issues.some((m) => /file on disk but not in MANIFEST: orphan\.txt/.test(m)), `expected orphan-file issue, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: an unmanifested vendored tree is caught, not silently skipped", () => {
  withTmpDir((dir) => {
    // Mirror the real hub/vendored + ui/vendored layout, plus one NEW,
    // deliberately unmanifested tree.
    mkdirSync(join(dir, "hub", "vendored", "ocg"), { recursive: true });
    mkdirSync(join(dir, "hub", "vendored", "anchor-suite"), { recursive: true });
    mkdirSync(join(dir, "hub", "vendored", "surprise-new-vendor"), { recursive: true });
    mkdirSync(join(dir, "ui", "vendored"), { recursive: true });
    const issues = collectUncoveredTreeIssues(dir);
    assert.ok(
      issues.some((m) => /hub\/vendored\/surprise-new-vendor.*not covered/.test(m)),
      `expected the new unmanifested tree to be flagged, got: ${JSON.stringify(issues)}`
    );
  });
});
