import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { openJournal } from "./journal.mjs";
import { loadContract, assertEgressAllowed, performEgress } from "./connector.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-connector-test-"));
const CONTRACT_PATH = join(HERE, "connectors", "google-drive-fetch.contract.json");

test("loadContract validates the schema and computes a stable contract_digest", () => {
  const { contract, contractDigest } = loadContract(CONTRACT_PATH);
  assert.equal(contract.connector_id, "google-drive.fetch");
  assert.match(contractDigest, /^sha256:[0-9a-f]{64}$/);
  const again = loadContract(CONTRACT_PATH);
  assert.equal(again.contractDigest, contractDigest);
});

test("loadContract rejects a contract missing a required field", () => {
  const dir = mkdtempSync(join(tmpdir(), "helm-connector-badcontract-"));
  const badPath = join(dir, "bad.json");
  writeFileSync(badPath, JSON.stringify({ connector_id: "x" }));
  assert.throws(() => loadContract(badPath), /connector contract invalid/);
});

test("assertEgressAllowed: host+method must both be in the contract allowlist", () => {
  const { contract } = loadContract(CONTRACT_PATH);
  assert.equal(assertEgressAllowed(contract, { host: "www.googleapis.com", method: "GET" }), true);
  assert.equal(assertEgressAllowed(contract, { host: "evil.example.com", method: "GET" }), false);
  assert.equal(assertEgressAllowed(contract, { host: "www.googleapis.com", method: "POST" }), false);
});

test("performEgress: unapproved host is blocked AND the transcript records the block", async () => {
  const { contract } = loadContract(CONTRACT_PATH);
  const db = openJournal(join(TMP, "blocked.db"));
  const originalFetch = globalThis.fetch;
  let fetchCalled = false;
  globalThis.fetch = async () => { fetchCalled = true; throw new Error("must not be called"); };

  await assert.rejects(
    () => performEgress(db, { contract, connectorId: "google-drive.fetch", url: "https://evil.example.com/x", method: "GET" }),
    /egress blocked/
  );
  assert.equal(fetchCalled, false, "fetch must never be reached for a blocked host");

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:google-drive.fetch");
  assert.equal(rows.length, 1);
  const entry = JSON.parse(rows[0].entry_json);
  assert.equal(entry.decision, "blocked");
  assert.equal(entry.destination_host, "evil.example.com");

  globalThis.fetch = originalFetch;
  db.close();
});

test("performEgress: approved host is allowed and the transcript records the allow", async () => {
  const { contract } = loadContract(CONTRACT_PATH);
  const db = openJournal(join(TMP, "allowed.db"));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(Buffer.from("file-bytes"), { status: 200 });

  const result = await performEgress(db, {
    contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/drive/v3/files/abc?alt=media", method: "GET",
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.toString("utf8"), "file-bytes");

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:google-drive.fetch");
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "allowed");

  globalThis.fetch = originalFetch;
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
