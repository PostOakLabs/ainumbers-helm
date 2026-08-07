// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { loadSignerConfig, writeSignerConfig, validateSignerConfig, SIGNER_CONFIG_FILE } from "./signer-config.mjs";

function freshHome() {
  const dir = mkdtempSync(join(tmpdir(), "signer-config-test-"));
  process.env.HELM_HOME = dir;
  return dir;
}

function validConfig() {
  const { publicKey } = generateKeyPairSync("ed25519");
  return {
    command: "/usr/local/bin/my-signer",
    args: ["--slot", "1"],
    algo: "ed25519",
    publicKeyDerBase64: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  };
}

test("loadSignerConfig returns null before any config is written", () => {
  const dir = freshHome();
  try {
    assert.equal(loadSignerConfig(), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeSignerConfig persists and loadSignerConfig reads it back", () => {
  const dir = freshHome();
  try {
    const written = writeSignerConfig(validConfig());
    assert.equal(written.command, "/usr/local/bin/my-signer");
    const loaded = loadSignerConfig();
    assert.equal(loaded.command, "/usr/local/bin/my-signer");
    assert.deepEqual(loaded.args, ["--slot", "1"]);
    assert.equal(loaded.timeoutMs, 10_000);
    assert.equal(loaded.maxOutputBytes, 8192);
    assert.ok(loaded.updatedAt);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("validateSignerConfig rejects a shell-string command shape smuggled as args", () => {
  const dir = freshHome();
  try {
    const cfg = validConfig();
    cfg.args = "--slot 1"; // string, not an array — must be rejected, never split on spaces
    assert.throws(() => validateSignerConfig(cfg), /args must be an array of strings/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("validateSignerConfig rejects empty command", () => {
  const dir = freshHome();
  try {
    const cfg = validConfig();
    cfg.command = "  ";
    assert.throws(() => validateSignerConfig(cfg), /command must be a non-empty string/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("validateSignerConfig rejects a non-ed25519 algo", () => {
  const dir = freshHome();
  try {
    const cfg = validConfig();
    cfg.algo = "rsa";
    assert.throws(() => validateSignerConfig(cfg), /algo must be "ed25519"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("validateSignerConfig rejects env values that are not strings", () => {
  const dir = freshHome();
  try {
    const cfg = validConfig();
    cfg.env = { FOO: 123 };
    assert.throws(() => validateSignerConfig(cfg), /env\["FOO"\] must be a string/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("validateSignerConfig rejects a malformed base64 public key", () => {
  const dir = freshHome();
  try {
    const cfg = validConfig();
    cfg.publicKeyDerBase64 = "";
    assert.throws(() => validateSignerConfig(cfg), /publicKeyDerBase64 must be a non-empty base64 string/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writeSignerConfig writes the config file", () => {
  const dir = freshHome();
  try {
    writeSignerConfig(validConfig());
    const path = join(dir, SIGNER_CONFIG_FILE);
    assert.ok(existsSync(path));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
