import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { cgCanon, manifestDigest } from "./manifest-digest.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const golden = JSON.parse(readFileSync(join(ROOT, "fixtures", "workflow-manifest", "golden.json"), "utf8"));

test("cgCanon sorts keys recursively, preserves array order", () => {
  const canon = cgCanon({ b: 1, a: [{ d: 2, c: 3 }] });
  assert.deepEqual(Object.keys(canon), ["a", "b"]);
  assert.deepEqual(Object.keys(canon.a[0]), ["c", "d"]);
});

test("manifestDigest is deterministic regardless of key order", async () => {
  const shuffled = { workflow_id: golden.workflow_id, manifest_version: golden.manifest_version, ...golden };
  const [a, b] = await Promise.all([manifestDigest(golden), manifestDigest(shuffled)]);
  assert.equal(a, b);
});

test("manifestDigest returns a sha256: prefixed 64-hex digest", async () => {
  const digest = await manifestDigest(golden);
  assert.match(digest, /^sha256:[0-9a-f]{64}$/);
});

test("manifestDigest changes when the manifest changes", async () => {
  const a = await manifestDigest(golden);
  const b = await manifestDigest({ ...golden, workflow_id: "different" });
  assert.notEqual(a, b);
});
