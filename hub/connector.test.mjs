import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { openJournal } from "./journal.mjs";
import { loadContract, assertEgressAllowed, performEgress, assertResolvedIpAllowed, __setHostResolverForTest } from "./connector.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-connector-test-"));
process.env.HELM_HOME = join(TMP, "home");
const CONTRACT_PATH = join(HERE, "connectors", "google-drive-fetch.contract.json");

// Real DNS isn't reachable/deterministic in the sandboxed test runner, so
// tests map the fixed hostnames they use to fixed, non-denied public IPs.
__setHostResolverForTest(async (hostname) => {
  if (hostname === "www.googleapis.com") return ["142.250.0.100"];
  throw new Error(`test resolver: unexpected hostname ${hostname}`);
});
process.on("exit", () => __setHostResolverForTest(null));

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

test("performEgress: fetch call carries a timeout signal (HELM-SEC-5 hardening)", async () => {
  const { contract } = loadContract(CONTRACT_PATH);
  const db = openJournal(join(TMP, "timeout-signal.db"));
  const originalFetch = globalThis.fetch;
  let seenSignal;
  globalThis.fetch = async (u, opts) => {
    seenSignal = opts.signal;
    return new Response(Buffer.from("ok"), { status: 200 });
  };

  await performEgress(db, {
    contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/drive/v3/files/abc?alt=media", method: "GET",
  });
  assert.ok(seenSignal instanceof AbortSignal, "performEgress must pass an AbortSignal to fetch");

  globalThis.fetch = originalFetch;
  db.close();
});

test("performEgress: redirect to a non-allowlisted host is blocked, not silently followed", async () => {
  const { contract } = loadContract(CONTRACT_PATH);
  const db = openJournal(join(TMP, "redirect-blocked.db"));
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (u, opts) => {
    calls++;
    assert.equal(opts.redirect, "manual", "must disable auto-follow so every hop is re-checked");
    if (calls === 1) {
      return new Response(null, { status: 302, headers: { location: "https://evil.example.com/steal" } });
    }
    throw new Error("must not follow redirect past the allowlist check");
  };

  await assert.rejects(
    () => performEgress(db, {
      contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/drive/v3/files/abc?alt=media", method: "GET",
    }),
    /egress blocked/
  );
  assert.equal(calls, 1, "the redirect target must never be fetched");

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:google-drive.fetch");
  assert.equal(rows.length, 2, "both the original allow and the redirect-target block are journaled");
  const entries = rows.map((r) => JSON.parse(r.entry_json));
  assert.equal(entries[0].destination_host, "www.googleapis.com");
  assert.equal(entries[0].decision, "allowed");
  assert.equal(entries[1].destination_host, "evil.example.com");
  assert.equal(entries[1].decision, "blocked");

  globalThis.fetch = originalFetch;
  db.close();
});

test("assertResolvedIpAllowed: rejects private/link-local/metadata IPs", async () => {
  await assert.rejects(() => assertResolvedIpAllowed("127.0.0.1"), /egress blocked/);
  await assert.rejects(() => assertResolvedIpAllowed("169.254.169.254"), /egress blocked/); // cloud metadata
  await assert.rejects(() => assertResolvedIpAllowed("10.0.0.5"), /egress blocked/);
  await assert.rejects(() => assertResolvedIpAllowed("192.168.1.1"), /egress blocked/);
  await assert.rejects(() => assertResolvedIpAllowed("::1"), /egress blocked/);
  await assert.rejects(() => assertResolvedIpAllowed("::ffff:127.0.0.1"), /egress blocked/); // IPv4-mapped
  await assert.rejects(() => assertResolvedIpAllowed("fe80::1"), /egress blocked/);
  await assert.doesNotReject(() => assertResolvedIpAllowed("8.8.8.8"));
});

test("performEgress: DNS-rebinding — allowlisted hostname resolving to a private IP is blocked, not fetched", async () => {
  const { contract } = loadContract(CONTRACT_PATH);
  const db = openJournal(join(TMP, "rebind-blocked.db"));
  __setHostResolverForTest(async (hostname) => {
    assert.equal(hostname, "www.googleapis.com");
    return ["169.254.169.254"]; // rebound to cloud metadata
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("must not be called"); };

  await assert.rejects(
    () => performEgress(db, {
      contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/drive/v3/files/abc?alt=media", method: "GET",
    }),
    /egress blocked/
  );

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:google-drive.fetch");
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "blocked");

  globalThis.fetch = originalFetch;
  __setHostResolverForTest(async (hostname) => {
    if (hostname === "www.googleapis.com") return ["142.250.0.100"];
    throw new Error(`test resolver: unexpected hostname ${hostname}`);
  });
  db.close();
});

test("performEgress: credential is attached at the boundary, connector caller never builds the header itself", async () => {
  const { contract } = loadContract(CONTRACT_PATH);
  const db = openJournal(join(TMP, "credential-boundary.db"));
  const { vaultSet } = await import("./vault.mjs");
  const { ref } = vaultSet("test:egress-boundary-token", { access_token: "boundary-secret-xyz" });

  const originalFetch = globalThis.fetch;
  let seenAuth;
  globalThis.fetch = async (u, opts) => {
    seenAuth = opts.headers.Authorization;
    return new Response(Buffer.from("ok"), { status: 200 });
  };

  await performEgress(db, {
    contract, connectorId: "google-drive.fetch", url: "https://www.googleapis.com/drive/v3/files/abc?alt=media", method: "GET",
    credential: { ref, scheme: "bearer" },
  });
  assert.equal(seenAuth, "Bearer boundary-secret-xyz");

  globalThis.fetch = originalFetch;
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
