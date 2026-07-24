// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "gen-version-feed.mjs");
const SCHEMA = join(HERE, "..", "schema", "version_notice.schema.json");

test("gen-version-feed writes a schema-valid, fact-only feed", () => {
  const dir = mkdtempSync(join(tmpdir(), "version-feed-"));
  const out = join(dir, "version.json");
  try {
    execFileSync("node", [
      SCRIPT,
      "--version", "1.2.3",
      "--published-at", "2026-08-01T00:00:00Z",
      "--release-url", "https://github.com/PostOakLabs/ainumbers-helm/releases/tag/v1.2.3",
      "--schema", SCHEMA,
      "--out", out,
    ]);
    const feed = JSON.parse(readFileSync(out, "utf8"));
    assert.equal(feed.latest_version, "1.2.3");
    assert.equal(feed.minimum_supported_version, "1.2.3");
    assert.equal(feed.release_url, "https://github.com/PostOakLabs/ainumbers-helm/releases/tag/v1.2.3");
    assert.equal(feed.published_at, "2026-08-01T00:00:00Z");
    const json = JSON.stringify(feed);
    assert.doesNotMatch(json, /business day|within \d+ day|SLA|guarantee/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("gen-version-feed rejects a leading-v version string", () => {
  const dir = mkdtempSync(join(tmpdir(), "version-feed-"));
  const out = join(dir, "version.json");
  try {
    assert.throws(() => {
      execFileSync("node", [
        SCRIPT,
        "--version", "v1.2.3",
        "--published-at", "2026-08-01T00:00:00Z",
        "--release-url", "https://github.com/PostOakLabs/ainumbers-helm/releases/tag/v1.2.3",
        "--schema", SCHEMA,
        "--out", out,
      ], { stdio: "pipe" });
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
