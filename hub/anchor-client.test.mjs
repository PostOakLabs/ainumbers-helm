// Live round-trip fixture against the SHIPPED Anchor Suite relay + a public
// OTS calendar (§4 HELM-H3 "done": anchor round-trip tests green). One CA and
// one calendar only — the relay's own rate-limit rule is 50 req/10s per IP
// (memory: project-ainumbers-cloudflare-housekeeping-2026-07-11), a single
// call per run never approaches it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import {
  anchorRfc3161, anchorOpenTimestamps, anchorForCheckpoint, buildQueueMarker,
  toCheckpointAnchorEntry, ANCHOR_QUEUE_MARKER_SCHEMA_REF, RELAY_CA_LIST, OTS_CALENDAR_LIST,
} from "./anchor-client.mjs";
import { buildCheckpoint, verifyCheckpoint } from "./checkpoint.mjs";
import { verifyAnchorBinding } from "../ui/lib/verify-bundle.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";
import { liveTest } from "../test-support/live.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

// Set BEFORE any dynamic import of keys.mjs/journal.mjs (both read HELM_HOME
// lazily via state-dir.mjs, but round-trip.test.mjs's convention is to fix
// this at module top so no test can race a env-var mutation mid-run).
const SEC3_TMP = mkdtempSync(join(tmpdir(), "helm-sec3-test-"));
process.env.HELM_HOME = SEC3_TMP;
const { loadOrCreateKeys, publicKeysOf } = await import("./keys.mjs");
const { openJournal, appendEntry } = await import("./journal.mjs");

function digestOf(text) {
  return createHash("sha256").update(text).digest("hex");
}

liveTest("anchor round-trip: rfc3161 relay returns a verifiable-shaped TimeStampResp", { timeout: 40_000 }, async () => {
  const hash = digestOf(`helm-h3-rfc3161-fixture-${Date.now()}`);
  const anchor = await anchorRfc3161(hash, { ca: "freetsa" });
  assert.equal(anchor.type, "rfc3161");
  assert.equal(anchor.anchored_hash, `sha256:${hash}`);
  assert.ok(RELAY_CA_LIST.includes(anchor.ca));
  const der = Buffer.from(anchor.der, "base64");
  assert.ok(der.length > 0);
  // DER SEQUENCE tag — the only format-level assertion made without a full
  // ASN.1 parser (that lives in the Verify view, HELM-U3, reusing the same
  // vendored pkijs code this client also imports).
  assert.equal(der[0], 0x30);
});

test("anchor round-trip: rejects an unknown relay CA before making a network call", async () => {
  await assert.rejects(() => anchorRfc3161("a".repeat(64), { ca: "not-a-real-ca" }));
});

liveTest("anchor round-trip: opentimestamps calendar returns a pending attestation", { timeout: 25_000 }, async () => {
  const hash = digestOf(`helm-h3-ots-fixture-${Date.now()}`);
  const anchor = await anchorOpenTimestamps(hash, { calendar: OTS_CALENDAR_LIST[0] });
  assert.equal(anchor.type, "opentimestamps");
  assert.equal(anchor.anchored_hash, `sha256:${hash}`);
  assert.equal(anchor.upgraded, false);
  assert.ok(Buffer.from(anchor.pending_proof, "base64").length > 0);
});

// HELM-P3-SEC-3 (R15-F5): the orchestrating caller anchorRfc3161()/
// anchorOpenTimestamps() never had — try/catch classifying failure into the
// schema's three reasons, never letting a relay failure abort checkpoint
// creation. All fetchImpl-injected (zero real network), same discipline as
// ui/lib/anchor-browser.test.mjs.
const HASH_HEX = digestOf("helm-p3-sec-3-fixture");

test("anchorForCheckpoint: offline (zero-egress) — no network call, skipped marker recorded", async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return { ok: true, headers: { get: () => "application/timestamp-reply" }, arrayBuffer: async () => new ArrayBuffer(0) }; };
  const { anchor, queueMarker } = await anchorForCheckpoint(HASH_HEX, { checkpointSeq: 7, offline: true, fetchImpl });
  assert.equal(called, false, "offline mode must never touch the network");
  assert.equal(anchor, undefined);
  assert.equal(queueMarker.status, "skipped");
  assert.equal(queueMarker.reason, "egress_blocked");
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA_REF, queueMarker), []);
});

test("anchorForCheckpoint: relay unreachable (network throw) — queued with relay_unreachable, never throws", async () => {
  const fetchImpl = async () => { throw new Error("ECONNREFUSED"); };
  const { anchor, queueMarker } = await anchorForCheckpoint(HASH_HEX, { checkpointSeq: 7, fetchImpl });
  assert.equal(anchor, undefined);
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_unreachable");
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA_REF, queueMarker), []);
});

test("anchorForCheckpoint: relay HTTP error — queued with relay_error, not silently dropped", async () => {
  const fetchImpl = async () => ({ ok: false, status: 503, headers: { get: () => null }, arrayBuffer: async () => new ArrayBuffer(0) });
  const { queueMarker } = await anchorForCheckpoint(HASH_HEX, { checkpointSeq: 7, fetchImpl });
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_error");
});

test("anchorForCheckpoint: unknown CA is a caller bug, not a relay condition — still throws", async () => {
  await assert.rejects(() => anchorForCheckpoint(HASH_HEX, { checkpointSeq: 7, ca: "not-a-real-ca" }));
});

test("buildQueueMarker: rejects a shape that would fail the schema (e.g. bad status)", () => {
  assert.throws(() => buildQueueMarker({ checkpointSeq: 1, status: "anchored", reason: "egress_blocked", relayUrl: "https://anchor.ainumbers.co/relay/freetsa" }));
});

test("fixture: golden anchor_queue_marker validates against the schema", () => {
  const golden = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "anchor_queue_marker", "golden.json"), "utf8"));
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA_REF, golden), []);
});

test("fixture: tampered anchor_queue_marker (status not in enum) fails the schema", () => {
  const tampered = JSON.parse(readFileSync(join(HERE, "..", "fixtures", "anchor_queue_marker", "tampered.json"), "utf8"));
  assert.ok(validate(ANCHOR_QUEUE_MARKER_SCHEMA_REF, tampered).length > 0);
});

// §5 exit-gate #1 ("relay-blocked, tool 100% functional"): an egress-blocked
// checkpoint is still a valid, verifiable signed object, and the offline
// verifier renders its queue marker as neutral "anchoring queued/skipped" —
// never as an error, never as "unrecognized anchor type".
test("egress-blocked run: checkpoint still builds/verifies, and the offline verifier renders the marker neutrally", async () => {
  const keys = loadOrCreateKeys();
  const publicKeys = publicKeysOf(keys);

  const db = openJournal(join(SEC3_TMP, "cp.db"));
  appendEntry(db, {
    streamId: "run-1",
    kind: "execution_state",
    entry: {
      period_start: "2026-07-24T00:00:00.000Z",
      period_end: "2026-07-24T00:00:01.000Z",
      reference_db_version: "kernels@2026-07-24",
      triggering_input_digest: `sha256:${"d".repeat(64)}`,
      humans_involved: [],
      state: "queued",
    },
  });

  const fetchImpl = async () => { throw new Error("network unreachable — all egress blocked"); };
  const { anchor, queueMarker } = await anchorForCheckpoint(HASH_HEX, { checkpointSeq: 1, fetchImpl });
  assert.equal(anchor, undefined);

  const checkpoint = buildCheckpoint(db, { checkpointSeq: 1, keys, anchors: [toCheckpointAnchorEntry({ queueMarker })] });
  const result = verifyCheckpoint(db, checkpoint, publicKeys);
  assert.equal(result.valid, true, "an unanchored/queued checkpoint is still a valid signed checkpoint");

  const [renderedAnchor] = result.statement.predicate.anchors;
  assert.equal(renderedAnchor.type, "queued");
  const binding = verifyAnchorBinding(renderedAnchor, checkpoint.journalRootDigest);
  assert.equal(binding.neutral, true);
  assert.equal(binding.status, "queued");
  assert.equal(binding.reason, "relay_unreachable");

  db.close();
});

test.after(() => rmSync(SEC3_TMP, { recursive: true, force: true }));
