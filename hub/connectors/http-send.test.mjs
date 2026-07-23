import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-http-send-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("../journal.mjs");
const { loadContract, __setHostResolverForTest } = await import("../connector.mjs");
const { vaultSet } = await import("../vault.mjs");
const { createHttpConnector, CONNECTOR_ID } = await import("./http-send.mjs");

__setHostResolverForTest(async (hostname) => {
  if (hostname === "api.example.com") return ["93.184.216.34"];
  throw new Error(`test resolver: unexpected hostname ${hostname}`);
});
process.on("exit", () => __setHostResolverForTest(null));

const ATTESTATION_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "..", "schema", "objects", "connector_attestation.schema.json"), "utf8")
);

test("http.send: happy path with a bearer credential produces a schema-valid attestation", async () => {
  const db = openJournal(join(TMP, "http-ok.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "http-send.contract.json"));
  const { ref: credentialRef } = vaultSet("test:http-cred", { access_token: "tok-abc" });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    assert.equal(new URL(url).host, "api.example.com");
    assert.equal(opts.headers.Authorization, "Bearer tok-abc");
    return new Response(Buffer.from('{"ok":true}'), { status: 200 });
  };

  const connector = createHttpConnector({ db, contract, contractDigest });
  await connector.init({ credentialRef });
  assert.deepEqual(await connector.selfTest(), { ok: true });

  const { attestation, payload, status } = await connector.send({
    url: "https://api.example.com/hook", method: "POST",
    runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
  });

  assert.equal(status, 200);
  assert.equal(payload.toString("utf8"), '{"ok":true}');
  assert.equal(attestation.connector_id, CONNECTOR_ID);
  const errs = validate(ATTESTATION_SCHEMA, attestation);
  assert.deepEqual(errs, []);

  await connector.dispose();
  globalThis.fetch = originalFetch;
  db.close();
});

test("http.send: a host outside the contract's allowlist is blocked + transcript-logged, no fetch ever fires", async () => {
  const db = openJournal(join(TMP, "http-blocked.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "http-send.contract.json"));

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("fetch must never be called for a blocked host");
  };

  const connector = createHttpConnector({ db, contract, contractDigest });
  await connector.init({});

  await assert.rejects(
    () => connector.send({
      url: "https://not-allowed.example/x", method: "GET",
      runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
    }),
    /egress blocked/
  );

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all(`egress:${CONNECTOR_ID}`);
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "blocked");

  globalThis.fetch = originalFetch;
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
