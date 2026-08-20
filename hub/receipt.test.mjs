import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-watch-receipt-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { getPack } = await import("./packs.mjs");
const { manifestDigest } = await import("./run.mjs");
const { createWatch, fireWatch } = await import("./watch-scheduler.mjs");
const { createUptimeHeartbeat } = await import("./uptime-record.mjs");
const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { verifyBundle, assembleBundle } = await import("./bundle.mjs");
const { computeFreshnessReceipt, sealFreshnessReceipt, exportFreshnessReceiptZip } = await import("./receipt.mjs");

const GATE_FREE_WORKFLOW_ID = "pack-agent-economy-fit";
const gateFreePack = getPack(GATE_FREE_WORKFLOW_ID);
assert.ok(gateFreePack, `fixture pack "${GATE_FREE_WORKFLOW_ID}" must exist in the compiled packs/ catalog for this test`);

const keys = loadOrCreateKeys();
const publicKeys = publicKeysOf(keys);

function dbAt(name) {
  return openJournal(join(TMP, name));
}

function baseInput(overrides = {}) {
  return {
    pack_ref: { pack_id: GATE_FREE_WORKFLOW_ID, pack_digest: manifestDigest(gateFreePack.manifest) },
    cadence: { unit: "hours", interval: 1 },
    inputs_source: { mode: "sample" },
    created_by: { id: "did:key:z6MkTestOperator" },
    consent_ref: "sha256:" + "c".repeat(64),
    ...overrides,
  };
}

test("computeFreshnessReceipt: 'ran' status after a fresh firing, within_window true, evidences carried", async () => {
  const db = dbAt("ran.db");
  const watch = createWatch(
    baseInput({ watch_id: "watch-receipt-ran", evidences: [{ framework: "DORA", control_id: "Art. 28" }] })
  );
  const fireAt = Date.parse(watch.created_at) + 3_700_000;
  await fireWatch(db, watch, { nowISO: new Date(fireAt).toISOString() });

  const receipt = computeFreshnessReceipt(db, "watch-receipt-ran", { nowFn: () => fireAt + 60_000 });
  assert.equal(receipt.status, "ran");
  assert.ok(receipt.journal_seq !== null);
  assert.ok(receipt.entry_digest?.startsWith("sha256:"));
  assert.equal(receipt.cadence_conformance.within_window, true);
  assert.deepEqual(receipt.evidences, [{ framework: "DORA", control_id: "Art. 28" }]);
  assert.equal(receipt.drift_window.duration_ms, 60_000);
  db.close();
});

test("computeFreshnessReceipt: never fired, helmd never continuously up -> no_evidence_of_run (never a miss)", () => {
  const db = dbAt("no-evidence.db");
  const watch = createWatch(baseInput({ watch_id: "watch-receipt-no-evidence", cadence: { unit: "hours", interval: 1 } }));
  const nowMs = Date.parse(watch.created_at) + 3_600_001; // past due, no heartbeat ever recorded

  const receipt = computeFreshnessReceipt(db, "watch-receipt-no-evidence", { nowFn: () => nowMs });
  assert.equal(receipt.status, "no_evidence_of_run");
  assert.equal(receipt.journal_seq, null);
  assert.equal(receipt.cadence_conformance.ran_at, null);
  db.close();
});

function fakeClock(startMs) {
  let nowMs = startMs;
  let tickFn = null;
  return {
    nowFn: () => nowMs,
    setIntervalFn: (fn) => { tickFn = fn; return { unref() {} }; },
    clearIntervalFn: () => { tickFn = null; },
    advance(ms) { nowMs += ms; if (tickFn) tickFn(); },
  };
}

test("computeFreshnessReceipt: never fired, helmd continuously up the whole window -> evidence_of_non_run (a real miss)", () => {
  const db = dbAt("non-run.db");
  const watch = createWatch(baseInput({ watch_id: "watch-receipt-non-run", cadence: { unit: "hours", interval: 1 } }));
  const createdMs = Date.parse(watch.created_at);

  const clock = fakeClock(createdMs);
  const heartbeat = createUptimeHeartbeat({ db, intervalMs: 600_000, nowFn: clock.nowFn, setIntervalFn: clock.setIntervalFn, clearIntervalFn: clock.clearIntervalFn });
  heartbeat.start();
  for (let i = 0; i < 6; i++) clock.advance(600_000); // six contiguous heartbeats spanning the 1h cadence, no gap
  heartbeat.stop();

  const receipt = computeFreshnessReceipt(db, "watch-receipt-non-run", { nowFn: () => createdMs + 3_600_001 });
  assert.equal(receipt.status, "evidence_of_non_run");
  db.close();
});

test("sealFreshnessReceipt: seals into a verifiable §26.4 object inside an assembled bundle", () => {
  const db = dbAt("seal.db");
  const watch = createWatch(baseInput({ watch_id: "watch-receipt-seal" }));
  const { sealed } = sealFreshnessReceipt(db, "watch-receipt-seal", keys, { nowFn: () => Date.now() });
  assert.equal(sealed.trust_label, "hash_verified");

  const bundle = assembleBundle({
    bundleId: "bundle-receipt-seal",
    runId: "watch-receipt-seal",
    workflowManifestDigest: watch.pack_ref.pack_digest,
    specs: [sealed],
    keys,
  });
  const result = verifyBundle(bundle, publicKeys);
  assert.deepEqual(result, { valid: true, reasons: [] });
  db.close();
});

test("TAMPERED-RECEIPT: a mutated freshness_receipt predicate is proven to FAIL verification", () => {
  const db = dbAt("tamper.db");
  const watch = createWatch(baseInput({ watch_id: "watch-receipt-tamper" }));
  const { sealed } = sealFreshnessReceipt(db, "watch-receipt-tamper", keys, { nowFn: () => Date.now() });
  const bundle = assembleBundle({
    bundleId: "bundle-receipt-tamper",
    runId: "watch-receipt-tamper",
    workflowManifestDigest: watch.pack_ref.pack_digest,
    specs: [sealed],
    keys,
  });

  const tampered = structuredClone(bundle);
  // Downgrade the observed status after the fact — exactly the attack a
  // freshness receipt exists to make impossible undetected.
  tampered.objects[0].envelope.payload = Buffer.from(
    JSON.stringify(JSON.parse(Buffer.from(tampered.objects[0].envelope.payload, "base64").toString("utf8")))
      .replace(/"status":"[a-z_]+"/, '"status":"ran"')
  ).toString("base64");

  const result = verifyBundle(tampered, publicKeys);
  console.log(`TAMPERED-RECEIPT verify result: valid=${result.valid} reasons=${JSON.stringify(result.reasons)}`);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.length > 0);
  db.close();
});

test("exportFreshnessReceiptZip: verifies OFFLINE via the shipped standalone verify chain (ui/lib/verify-bundle.mjs)", async () => {
  const db = dbAt("export.db");
  const watch = createWatch(baseInput({ watch_id: "watch-receipt-export" }));
  const fireAt = Date.parse(watch.created_at) + 3_700_000;
  await fireWatch(db, watch, { nowISO: new Date(fireAt).toISOString() });

  const result = await exportFreshnessReceiptZip(db, "watch-receipt-export", keys, { nowFn: () => fireAt + 60_000 });
  console.log(`exportFreshnessReceiptZip offline-verify result: valid=${result.valid} reasons=${JSON.stringify(result.reasons)} status=${result.receipt.status}`);
  assert.equal(result.valid, true);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.receipt.status, "ran");
  assert.ok(result.zip.length > 0);
  db.close();
});
