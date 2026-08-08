// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-VERIFY-CLI-1 §1.3 — zero-network is a TESTED property, not an assumed
// one (phil condition 8). Spawns `helmd verify` under a preload that
// overrides fetch/dns.lookup/net.Socket.connect to throw; base verify (and
// --anchor-full) must complete cleanly under it, and a THIRD canary run that
// deliberately calls fetch under the same preload must trip — proving the
// harness actually catches a network call rather than passing vacuously.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { DEMO_PUBLIC_KEYS, DEMO_GOLDEN_BUNDLE } from "../ui/fixtures/verify-demo.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VERIFY_ENTRY = join(HERE, "verify.mjs");
const PRELOAD = join(HERE, "verify-network-guard-preload.cjs");

function fixtures() {
  const dir = mkdtempSync(join(tmpdir(), "helm-verify-cli-1-net-"));
  const bundlePath = join(dir, "bundle.json");
  const keysPath = join(dir, "keys.json");
  writeFileSync(bundlePath, JSON.stringify(DEMO_GOLDEN_BUNDLE));
  writeFileSync(keysPath, JSON.stringify(DEMO_PUBLIC_KEYS));
  return { bundlePath, keysPath };
}

function runUnderPreload(args) {
  return spawnSync(process.execPath, ["--require", PRELOAD, VERIFY_ENTRY, ...args], { encoding: "utf8" });
}

test("canary: the preload actually traps a network call (proves the harness isn't vacuous)", () => {
  const result = spawnSync(
    process.execPath,
    ["--require", PRELOAD, "-e", "try { fetch('http://example.invalid'); process.exit(9); } catch (e) { process.exit(e.message.includes('NETWORK_BLOCKED') ? 1 : 8); }"],
    { encoding: "utf8" }
  );
  assert.equal(result.status, 1, `expected the canary fetch to trip NETWORK_BLOCKED, got status=${result.status} stderr=${result.stderr}`);
});

test("base `helmd verify` completes cleanly under the network-blocking preload (zero-network by construction)", () => {
  const { bundlePath, keysPath } = fixtures();
  const result = runUnderPreload([bundlePath, "--keys", keysPath, "--json"]);
  assert.equal(result.status, 0, `unexpected non-zero exit under preload: stderr=${result.stderr}`);
  assert.ok(!/NETWORK_BLOCKED/.test(result.stderr), `verify attempted a network call: ${result.stderr}`);
  const out = JSON.parse(result.stdout);
  assert.equal(out.valid, true);
});

test("`helmd verify --anchor-full` ALSO completes cleanly under the same preload (pinned-root design makes no network call either)", () => {
  const { bundlePath, keysPath } = fixtures();
  const result = runUnderPreload([bundlePath, "--keys", keysPath, "--json", "--anchor-full"]);
  assert.equal(result.status, 0, `unexpected non-zero exit under preload: stderr=${result.stderr}`);
  assert.ok(!/NETWORK_BLOCKED/.test(result.stderr), `--anchor-full attempted a network call: ${result.stderr}`);
});
