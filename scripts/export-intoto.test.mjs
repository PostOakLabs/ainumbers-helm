// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-INTOTO-EXPORT-1 done-criterion tests: statement validates against the
// pinned predicate schema; the DSSE envelope verifies with the install's
// public keys; and a tampered execution_hash in the predicate fails
// signature verification (RED-then-GREEN: this suite is the row's gate
// evidence, run twice and quoted in the checkoff).
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ENTRY = join(ROOT, "scripts", "export-intoto.mjs");
const HELMD = join(ROOT, "bin", "helmd.mjs");

process.env.HELM_HOME = mkdtempSync(join(tmpdir(), "helm-intoto-export-test-"));

const { loadOrCreateKeys, publicKeysOf } = await import("../hub/keys.mjs");
const { assembleBundle } = await import("../hub/bundle.mjs");
const { verifyEnvelope } = await import("../hub/envelope.mjs");
const { createHash } = await import("node:crypto");

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);

const RUN_ID = "run-intoto-export-1";
const WF_DIGEST = "sha256:" + "a".repeat(64);
const EXECUTION_HASH = "sha256:" + "b".repeat(64);
const KERNEL_DIGEST = "sha256:" + "c".repeat(64);

function sealedSpecs(keysObject) {
  return [
    {
      kind: "connector_attestation",
      subject: [{ name: "payload", digest: { sha256: "d".repeat(64) } }],
      predicate: {
        run_id: RUN_ID,
        workflow_manifest_digest: WF_DIGEST,
        connector_id: "google-drive.fetch",
        payload_digest: "sha256:" + "d".repeat(64),
      },
    },
    {
      kind: "step_result",
      subject: [{ name: "execution_hash", digest: { sha256: EXECUTION_HASH.replace(/^sha256:/, "") } }],
      predicate: {
        run_id: RUN_ID,
        workflow_id: "wf-intoto-export-1",
        step_id: "nodes:n1",
        output_digest: "sha256:" + "e".repeat(64),
      },
    },
    {
      kind: "attested_artifact",
      subject: [{ name: "artifact", digest: { sha256: "f".repeat(64) } }],
      predicate: { run_id: RUN_ID, execution_hash: EXECUTION_HASH, kernel_digest: KERNEL_DIGEST },
      trustLabel: "hash_verified",
    },
  ];
}

const bundle = assembleBundle({
  bundleId: "bundle-intoto-export-1",
  runId: RUN_ID,
  workflowManifestDigest: WF_DIGEST,
  specs: sealedSpecs(keys),
  keys,
});

const TMPDIR = mkdtempSync(join(tmpdir(), "helm-intoto-export-out-"));
const bundlePath = join(TMPDIR, "bundle.json");
writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));

// Keep childish temptations out of the suite: cleanup at exit, never a
// stray rm of the shared worktree.
process.on("exit", () => {
  try { rmSync(TMPDIR, { recursive: true, force: true }); } catch { /* best effort */ }
});

function statementOf(envelope) {
  return JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
}

test("export-intoto (CLI): writes a dual-signed DSSE envelope and exits 0", () => {
  const out = join(TMPDIR, "statement.json");
  let stdout;
  try {
    stdout = execFileSync(process.execPath, [ENTRY, bundlePath, "--out", out], { encoding: "utf8" });
  } catch (err) {
    throw new Error(`export-intoto exited ${err.status}: ${err.stderr}`);
  }
  assert.match(stdout, /wrote/);
  const envelope = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(envelope.payloadType, "application/vnd.in-toto+json");
  const algs = envelope.signatures.map((s) => s.alg).sort();
  assert.deepEqual(algs, ["EdDSA", "ML-DSA-44"]);
});

test("the exported statement is an in-toto Statement v1 whose predicate validates against the pinned schema", async () => {
  const out = join(TMPDIR, "statement.json");
  execFileSync(process.execPath, [ENTRY, bundlePath, "--out", out], { encoding: "utf8" });
  const envelope = JSON.parse(readFileSync(out, "utf8"));
  const statement = statementOf(envelope);

  assert.equal(statement._type, "https://in-toto.io/Statement/v1");
  assert.equal(statement.predicateType, "https://ainumbers.co/attestation/helm-run/v1");
  // subject = the bundle FILE's own bytes, name + sha256
  const fileText = readFileSync(bundlePath, "utf8");
  assert.equal(statement.subject[0].name, "bundle.json");
  assert.equal(statement.subject[0].digest.sha256, createHash("sha256").update(fileText).digest("hex"));

  const { validate } = await import("./lib/schema-validator.mjs");
  const schema = JSON.parse(readFileSync(join(ROOT, "schema", "predicates", "helm-run-v1.schema.json"), "utf8"));
  assert.deepEqual(validate(schema, statement.predicate), []);

  assert.equal(statement.predicate.run_id, RUN_ID);
  assert.equal(statement.predicate.workflow_id, "wf-intoto-export-1");
  assert.equal(statement.predicate.manifest_digest, WF_DIGEST);
  assert.equal(statement.predicate.execution_hash, EXECUTION_HASH);
  assert.equal(statement.predicate.kernel_digest, KERNEL_DIGEST);
  assert.deepEqual(
    statement.predicate.steps,
    [{ step_id: "nodes:n1", output_digest: "sha256:" + "e".repeat(64) }]
  );
  assert.deepEqual(statement.predicate.trust_labels, ["connector_asserted", "hash_verified", "kernel_verified"]);
  assert.equal(statement.predicate.bundle_sha256, `sha256:${statement.subject[0].digest.sha256}`);
});

test("the exported DSSE envelope verifies with the install's public keys", () => {
  const out = join(TMPDIR, "statement.json");
  execFileSync(process.execPath, [ENTRY, bundlePath, "--out", out], { encoding: "utf8" });
  const envelope = JSON.parse(readFileSync(out, "utf8"));
  const result = verifyEnvelope(envelope, publicKeys);
  assert.equal(result.valid, true);
  assert.equal(result.ed25519, true);
  assert.equal(result.mldsa44, true);
});

test("RED-then-GREEN under tamper: a tampered execution_hash in the predicate fails signature verification", () => {
  const out = join(TMPDIR, "tampered.json");
  execFileSync(process.execPath, [ENTRY, bundlePath, "--out", out], { encoding: "utf8" });
  const envelope = JSON.parse(readFileSync(out, "utf8"));

  // Tamper INSIDE the payload: flip the execution_hash and re-encode, leaving
  // every signature byte untouched. Even one byte of predicate change must
  // break BOTH signatures — the envelope covers the full statement, so no
  // post-issuance edit can be minted a valid signature.
  const statement = statementOf(envelope);
  statement.predicate.execution_hash = "sha256:" + "5".repeat(64);
  const tampered = { ...envelope, payload: Buffer.from(JSON.stringify(statement), "utf8").toString("base64") };

  const result = verifyEnvelope(tampered, publicKeys);
  assert.equal(result.valid, false);
  assert.equal(result.ed25519, false);
});

test("helmd export-intoto dispatch works through the thin wrapper", () => {
  const out = join(TMPDIR, "helmd-statement.json");
  let stdout;
  try {
    stdout = execFileSync(process.execPath, [HELMD, "export-intoto", bundlePath, "--out", out], { encoding: "utf8" });
  } catch (err) {
    throw new Error(`helmd export-intoto exited ${err.status}: ${err.stderr}`);
  }
  assert.match(stdout, /wrote/);
  const envelope = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(verifyEnvelope(envelope, publicKeys).valid, true);
});

test("the --help text lists the new verb and exit contract", () => {
  const stdout = execFileSync(process.execPath, [HELMD, "--help"], { encoding: "utf8" });
  assert.match(stdout, /export-intoto <bundle\.json>/);
});

test("refuses to export a bundle that is not in the on-disk evidence-bundle shape (exit 1, nothing written)", () => {
  const badPath = join(TMPDIR, "not-a-bundle.json");
  writeFileSync(badPath, JSON.stringify({ hello: "world" }));
  const out = join(TMPDIR, "never.json");
  try {
    execFileSync(process.execPath, [ENTRY, badPath, "--out", out], { encoding: "utf8" });
    assert.fail("export of a non-bundle must fail");
  } catch (err) {
    assert.equal(err.status, 1);
    assert.match(err.stderr, /not a Helm evidence bundle/);
    assert.throws(() => readFileSync(out), "no output file may exist on an export failure");
  }
});
