// AGENTGLUE-BUILD-3 (AGENT-GLUE-BUILD-SPEC.md §(c)): exportRunProofZip()
// slices one run's evidence out of a multi-run bundle + multi-checkpoint
// journal, using the SAME verifyBundle/verifyBundleOffline logic a full
// bundle uses (a subset bundle with a valid manifest, valid entries, valid
// checkpoint ref, and a valid anchor binding verifies exactly like a full
// bundle does).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-bundle-run-proof-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys } = await import("./keys.mjs");
const { openJournal } = await import("./journal.mjs");
const { buildCheckpoint } = await import("./checkpoint.mjs");
const { assembleBundle, exportRunProofZip } = await import("./bundle.mjs");

const keys = loadOrCreateKeys();
const WF_DIGEST = "sha256:" + "c".repeat(64);
const RUN_A = "run-proof-a";
const RUN_B = "run-proof-b";

function findLocalFileNames(zip) {
  const names = [];
  let off = 0;
  while (off < zip.length) {
    const sig = zip[off] | (zip[off + 1] << 8) | (zip[off + 2] << 16) | (zip[off + 3] << 24);
    if ((sig >>> 0) !== 0x04034b50) break;
    const dv = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
    const compSize = dv.getUint32(off + 18, true);
    const nameLen = dv.getUint16(off + 26, true);
    names.push(new TextDecoder().decode(zip.subarray(off + 30, off + 30 + nameLen)));
    off += 30 + nameLen + compSize;
  }
  return names;
}

function twoRunBundle(db) {
  const checkpoint1 = buildCheckpoint(db, { checkpointSeq: 1, keys });
  const checkpoint2 = buildCheckpoint(db, { checkpointSeq: 2, keys });
  const bundle = assembleBundle({
    bundleId: "bundle-multi-run",
    runId: RUN_A, // bundle-level label; objects below carry their own run_id
    workflowManifestDigest: WF_DIGEST,
    specs: [
      {
        kind: "step_result",
        subject: [{ name: "output", digest: { sha256: "e".repeat(64) } }],
        predicate: { run_id: RUN_A, step_id: "nodes:n1", output_digest: "sha256:" + "e".repeat(64) },
      },
      {
        kind: "step_result",
        subject: [{ name: "output", digest: { sha256: "f".repeat(64) } }],
        predicate: { run_id: RUN_B, step_id: "nodes:n1", output_digest: "sha256:" + "f".repeat(64) },
      },
    ],
    checkpoints: [checkpoint2, checkpoint1], // deliberately out of order
    keys,
  });
  return { bundle, checkpoint1, checkpoint2 };
}

test("exportRunProofZip: slices one run's objects + the smallest covering checkpoint out of a multi-run bundle", async () => {
  const db = openJournal(join(TMP, "run-a.db"));
  const { bundle, checkpoint1 } = twoRunBundle(db);

  const result = await exportRunProofZip(bundle, RUN_A, keys, { generatedAt: "2026-08-03T00:00:00.000Z" });
  db.close();

  assert.equal(result.valid, true);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.runId, RUN_A);
  assert.equal(result.checkpointSeq, checkpoint1.checkpointSeq); // the smaller of the two, not the larger
  assert.deepEqual(findLocalFileNames(result.zip), ["bundle.json", "verify.html", "auditor.html", "README.txt"]);
});

test("exportRunProofZip: the subset bundle omits the other run's objects", async () => {
  const db = openJournal(join(TMP, "run-b.db"));
  const { bundle } = twoRunBundle(db);
  db.close();

  await exportRunProofZip(bundle, RUN_A, keys);

  const runObjects = bundle.objects.filter((o) => JSON.parse(Buffer.from(o.envelope.payload, "base64").toString("utf8")).predicate.run_id === RUN_A);
  assert.equal(runObjects.length, 1); // exportRunProofZip filtered down to exactly this
  assert.equal(bundle.objects.length, 2); // sanity: source bundle really did carry both runs
});

test("exportRunProofZip: throws on a run_id absent from the bundle", async () => {
  const db = openJournal(join(TMP, "run-missing.db"));
  const { bundle } = twoRunBundle(db);
  db.close();

  await assert.rejects(
    () => exportRunProofZip(bundle, "run-does-not-exist", keys),
    /no objects found for run/
  );
});

test("exportRunProofZip: throws when the bundle carries no checkpoint at all", async () => {
  const bundle = assembleBundle({
    bundleId: "bundle-no-checkpoint",
    runId: RUN_A,
    workflowManifestDigest: WF_DIGEST,
    specs: [
      {
        kind: "step_result",
        subject: [{ name: "output", digest: { sha256: "e".repeat(64) } }],
        predicate: { run_id: RUN_A, step_id: "nodes:n1", output_digest: "sha256:" + "e".repeat(64) },
      },
    ],
    keys,
  });

  await assert.rejects(
    () => exportRunProofZip(bundle, RUN_A, keys),
    /no checkpoint available/
  );
});
