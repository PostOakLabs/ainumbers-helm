import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../../scripts/lib/schema-validator.mjs";
import { openJournal } from "../journal.mjs";
import { loadContract } from "../connector.mjs";
import { createInboundWebhookConnector, CONNECTOR_ID } from "./inbound-webhook.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-webhook-test-"));
const ATTESTATION_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "..", "schema", "objects", "connector_attestation.schema.json"), "utf8")
);

test("inbound-webhook: accepted source produces a schema-valid connector_attestation, no fetch call", async () => {
  const db = openJournal(join(TMP, "webhook.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "inbound-webhook.contract.json"));

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("inbound-webhook must never make an outbound call in Phase 1"); };

  const connector = createInboundWebhookConnector({ db, contract, contractDigest });
  await connector.init({});
  assert.deepEqual(await connector.selfTest(), { ok: true });

  const { attestation } = await connector.send({
    sourceHost: "hooks.n8n.example",
    method: "POST",
    body: JSON.stringify({ step: "reconcile", status: "done" }),
    runId: "run-1",
    workflowManifestDigest: "sha256:" + "a".repeat(64),
  });

  assert.equal(attestation.connector_id, CONNECTOR_ID);
  const errs = validate(ATTESTATION_SCHEMA, attestation);
  assert.deepEqual(errs, []);

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:inbound-webhook");
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "allowed");

  await connector.dispose();
  globalThis.fetch = originalFetch;
  db.close();
});

test("inbound-webhook: unapproved source host is blocked and the transcript records the block", async () => {
  const db = openJournal(join(TMP, "webhook-blocked.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "inbound-webhook.contract.json"));
  const connector = createInboundWebhookConnector({ db, contract, contractDigest });
  await connector.init({});

  await assert.rejects(
    () => connector.send({
      sourceHost: "attacker.example", method: "POST", body: "{}",
      runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
    }),
    /blocked/
  );

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all("egress:inbound-webhook");
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "blocked");
  assert.equal(JSON.parse(rows[0].entry_json).destination_host, "attacker.example");
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
