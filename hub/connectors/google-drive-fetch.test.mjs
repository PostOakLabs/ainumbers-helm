import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-gdrive-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("../journal.mjs");
const { loadContract, __setHostResolverForTest } = await import("../connector.mjs");
const { vaultSet } = await import("../vault.mjs");
const { createGoogleDriveFetchConnector, CONNECTOR_ID } = await import("./google-drive-fetch.mjs");

// Real DNS isn't reachable/deterministic in the sandboxed test runner.
__setHostResolverForTest(async (hostname) => {
  if (hostname === "www.googleapis.com") return ["142.250.0.100"];
  throw new Error(`test resolver: unexpected hostname ${hostname}`);
});
process.on("exit", () => __setHostResolverForTest(null));

const ATTESTATION_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "..", "schema", "objects", "connector_attestation.schema.json"), "utf8")
);

test("google-drive.fetch: happy path produces a schema-valid connector_attestation", async () => {
  const db = openJournal(join(TMP, "gdrive.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "google-drive-fetch.contract.json"));
  const { ref: tokenRef } = vaultSet("test:gdrive-token", { access_token: "at-123" });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    assert.equal(new URL(url).host, "www.googleapis.com");
    assert.equal(opts.headers.Authorization, "Bearer at-123");
    return new Response(Buffer.from("hello drive"), { status: 200 });
  };

  const connector = createGoogleDriveFetchConnector({ db, contract, contractDigest });
  await connector.init({ tokenRef });
  assert.deepEqual(await connector.selfTest(), { ok: true });

  const { attestation, payload } = await connector.send({
    fileId: "file-1", runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
  });

  assert.equal(payload.toString("utf8"), "hello drive");
  assert.equal(attestation.connector_id, CONNECTOR_ID);
  assert.equal(attestation.contract_digest, contractDigest);
  const errs = validate(ATTESTATION_SCHEMA, attestation);
  assert.deepEqual(errs, []);

  await connector.dispose();
  globalThis.fetch = originalFetch;
  db.close();
});

test("google-drive.fetch: an unapproved host never reaches selfTest's token, egress still blocks", async () => {
  const db = openJournal(join(TMP, "gdrive-blocked.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "google-drive-fetch.contract.json"));
  const { ref: tokenRef } = vaultSet("test:gdrive-token-2", { access_token: "at-456" });
  const tampered = { ...contract, allowed_hosts: ["not-googleapis.example"] };

  const connector = createGoogleDriveFetchConnector({ db, contract: tampered, contractDigest });
  await connector.init({ tokenRef });

  await assert.rejects(
    () => connector.send({ fileId: "file-1", runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64) }),
    /egress blocked/
  );

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:google-drive.fetch");
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "blocked");
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
