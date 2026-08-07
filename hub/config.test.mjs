// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-ANCHOR-DEFAULT-FLIP-1: anchoring must default OFF (opt-in) for both a
// fresh install (no config.json yet) and an existing config.json that
// predates this row (so doesn't mention anchorOnCheckpoint at all) — the
// second case is the one that actually matters: every install that ran
// before this WU has a config.json on disk with no anchorOnCheckpoint key,
// and `parsed.anchorOnCheckpoint ?? false` is what flips ITS behavior, not
// just a brand new install's.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-config-test-"));
process.env.HELM_HOME = TMP;
after(() => rmSync(TMP, { recursive: true, force: true }));

const { loadConfig } = await import("./config.mjs");

test("loadConfig: fresh install (no config.json yet) defaults anchorOnCheckpoint to false", () => {
  const config = loadConfig();
  assert.equal(config.anchorOnCheckpoint, false);
  assert.equal(config.relayBase, "https://anchor.ainumbers.co");
  assert.equal(config.ca, "freetsa");
});

test("loadConfig: a pre-existing config.json with no anchorOnCheckpoint key also defaults to false", () => {
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: 4173 }));
  const config = loadConfig();
  assert.equal(config.anchorOnCheckpoint, false);
});

test("loadConfig: explicit anchorOnCheckpoint: true is honored (opt-in)", () => {
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: 4173, anchorOnCheckpoint: true }));
  const config = loadConfig();
  assert.equal(config.anchorOnCheckpoint, true);
});

test("loadConfig: relayBase/ca are operator-settable, default relay stays unchanged when unset", () => {
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: 4173, relayBase: "https://freetsa.org", ca: "digicert" }));
  const config = loadConfig();
  assert.equal(config.relayBase, "https://freetsa.org");
  assert.equal(config.ca, "digicert");
});

test("loadConfig: an unknown ca is rejected rather than silently mis-anchoring", () => {
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: 4173, ca: "not-a-real-ca" }));
  assert.throws(() => loadConfig(), /ca.*must be one of/);
});

// HELIOS-CONFIG-1: heliosSidecar mirrors anchorOnCheckpoint's opt-out shape —
// same fresh-install and pre-existing-file-with-no-key coverage.
test("loadConfig: fresh install (no config.json yet) defaults heliosSidecar to disabled/empty", () => {
  rmSync(join(TMP, "config.json"), { force: true });
  const config = loadConfig();
  assert.deepEqual(config.heliosSidecar, {
    enabled: false,
    executionRpcUrl: "",
    consensusRpcUrl: "",
    network: "mainnet",
  });
});

test("loadConfig: a pre-existing config.json with no heliosSidecar key also defaults to disabled", () => {
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: 4173 }));
  const config = loadConfig();
  assert.equal(config.heliosSidecar.enabled, false);
  assert.equal(config.heliosSidecar.executionRpcUrl, "");
  assert.equal(config.heliosSidecar.consensusRpcUrl, "");
  assert.equal(config.heliosSidecar.network, "mainnet");
});

test("loadConfig: explicit heliosSidecar block is honored (opt-in)", () => {
  writeFileSync(
    join(TMP, "config.json"),
    JSON.stringify({
      port: 4173,
      heliosSidecar: {
        enabled: true,
        executionRpcUrl: "https://eth-mainnet.example/rpc",
        consensusRpcUrl: "https://beacon.example/",
        network: "mainnet",
      },
    })
  );
  const config = loadConfig();
  assert.equal(config.heliosSidecar.enabled, true);
  assert.equal(config.heliosSidecar.executionRpcUrl, "https://eth-mainnet.example/rpc");
  assert.equal(config.heliosSidecar.consensusRpcUrl, "https://beacon.example/");
});

test("loadConfig: a partial heliosSidecar block (only enabled set) fills the rest with defaults", () => {
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: 4173, heliosSidecar: { enabled: true } }));
  const config = loadConfig();
  assert.equal(config.heliosSidecar.enabled, true);
  assert.equal(config.heliosSidecar.executionRpcUrl, "");
  assert.equal(config.heliosSidecar.consensusRpcUrl, "");
  assert.equal(config.heliosSidecar.network, "mainnet");
});
