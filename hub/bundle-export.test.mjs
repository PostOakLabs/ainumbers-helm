// HELM-P3-V9: exportBundleZip() packages an assembled bundle into bundle.zip
// (bundle.json + verify.html + auditor.html + README.txt). Proves the golden
// path verifies at export time AND that a tampered bundle is caught — same
// gate the row's "virgin-machine test" (spec §5 gate 7) exercises manually,
// automated here against the real WebCrypto verify chain (Node 22.5+ ships
// globalThis.crypto.subtle, so this runs the actual embedded-in-verify.html
// code path, not a stand-in).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-bundle-export-test-"));
process.env.HELM_HOME = TMP;

const { loadOrCreateKeys } = await import("./keys.mjs");
const { assembleBundle, exportBundleZip, browserPublicKeys } = await import("./bundle.mjs");

const keys = loadOrCreateKeys();
const RUN_ID = "run-bundle-export-1";
const WF_DIGEST = "sha256:" + "c".repeat(64);

function fixtureSpecs() {
  return [
    {
      kind: "connector_attestation",
      subject: [{ name: "payload", digest: { sha256: "d".repeat(64) } }],
      predicate: { run_id: RUN_ID, connector_id: "google-drive.fetch", payload_digest: "sha256:" + "d".repeat(64) },
    },
    {
      kind: "step_result",
      subject: [{ name: "execution_hash", digest: { sha256: "e".repeat(64) } }],
      predicate: { run_id: RUN_ID, step_id: "nodes:n1", output_digest: "sha256:" + "e".repeat(64) },
    },
  ];
}

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

test("exportBundleZip: golden bundle verifies and ships all four files", async () => {
  const bundle = assembleBundle({ bundleId: "bundle-export-1", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys });
  const result = await exportBundleZip(bundle, keys, { generatedAt: "2026-07-24T00:00:00.000Z" });
  assert.equal(result.valid, true);
  assert.deepEqual(result.reasons, []);
  assert.deepEqual(findLocalFileNames(result.zip), ["bundle.json", "verify.html", "auditor.html", "README.txt"]);
});

test("exportBundleZip: a tampered bundle is caught at export time (fails visibly, still ships for inspection)", async () => {
  const bundle = assembleBundle({ bundleId: "bundle-export-2", runId: RUN_ID, workflowManifestDigest: WF_DIGEST, specs: fixtureSpecs(), keys });
  bundle.objects[0].envelope.signatures[0].sig = Buffer.from("not a real signature").toString("base64");
  const result = await exportBundleZip(bundle, keys, { generatedAt: "2026-07-24T00:00:00.000Z" });
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("entry_envelope_invalid")));
});

test("browserPublicKeys: converts the Node keypair to the WebCrypto SPKI shape verify.html expects", () => {
  const pk = browserPublicKeys(keys);
  assert.equal(typeof pk.ed25519SpkiB64, "string");
  assert.equal(typeof pk.mldsa44B64, "string");
  assert.ok(pk.ed25519SpkiB64.length > 0);
});
