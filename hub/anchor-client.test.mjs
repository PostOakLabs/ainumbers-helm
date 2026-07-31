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

const HERE = dirname(fileURLToPath(import.meta.url));

// Set BEFORE any dynamic import of keys.mjs/journal.mjs/anchor-client.mjs
// (all read HELM_HOME lazily via state-dir.mjs) — round-trip.test.mjs's
// convention, fixing this at module top so no test can race an env-var
// mutation mid-run. HELM-ANCHOR-RETRY-1: anchorForCheckpoint now persists
// queued markers here too (statePath() → HELM_HOME/anchor-queue.json), so
// this same tmp dir keeps that off the real ~/.helm as well.
const SEC3_TMP = mkdtempSync(join(tmpdir(), "helm-sec3-test-"));
process.env.HELM_HOME = SEC3_TMP;

const {
  anchorRfc3161, anchorOpenTimestamps, anchorForCheckpoint, buildQueueMarker,
  toCheckpointAnchorEntry, ANCHOR_QUEUE_MARKER_SCHEMA_REF, RELAY_CA_LIST, OTS_CALENDAR_LIST,
} = await import("./anchor-client.mjs");
const { buildCheckpoint, verifyCheckpoint } = await import("./checkpoint.mjs");
const { verifyAnchorBinding } = await import("../ui/lib/verify-bundle.mjs");
const { validate } = await import("../scripts/lib/schema-validator.mjs");
const { liveTest } = await import("../test-support/live.mjs");
const { verifyRfc3161, FREETSA_ROOT_PEM, extractMessageImprintHex } = await import("./vendored/ocg/kernels/_rfc3161.mjs");
const { derSeq, derInt, derEnc } = await import("./vendored/ocg/kernels/_anchor-testutil.mjs");
const { loadAnchorQueue } = await import("./anchor-queue.mjs");
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
  // phil's non-negotiable (this row's contract): a marker the operator chose
  // NOT to anchor (offline/egress_blocked) must never become a retry the
  // client dials out for on its own later.
  assert.deepEqual(loadAnchorQueue(), [], "an offline/skipped marker must never be persisted for retry");
});

test("anchorForCheckpoint: relay unreachable (network throw) — queued with relay_unreachable, never throws", async () => {
  const fetchImpl = async () => { throw new Error("ECONNREFUSED"); };
  const { anchor, queueMarker } = await anchorForCheckpoint(HASH_HEX, { checkpointSeq: 7, fetchImpl });
  assert.equal(anchor, undefined);
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_unreachable");
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA_REF, queueMarker), []);
  // G1: this is the specific gap the row exists to close — the marker must
  // survive OUTSIDE the (not-yet-signed) checkpoint, on disk, so a later
  // drain pass can find it.
  const persisted = loadAnchorQueue().find((e) => e.checkpoint_seq === 7);
  assert.ok(persisted, "a queued marker must be persisted to the anchor queue, not just returned");
  assert.equal(persisted.status, "queued");
  assert.equal(persisted.reason, "relay_unreachable");
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

// HELM-ANCHOR-TSR-1: the relay's real HTTP body is a full TimeStampResp =
// SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL } —
// every fixture/offline test above stubs a BARE ContentInfo, which is why the
// live-net gate was the only thing that ever caught this. These run 100%
// offline (fetchImpl-injected, zero network) so the fix is provable without
// depending on a cron job nobody watches.
const FIXTURE = JSON.parse(readFileSync(
  join(HERE, "vendored", "ocg", "kernels", "fixtures", "anchor-binding.fixture.json"), "utf8",
));
const BARE_TOKEN_B64 = FIXTURE.artifact.anchor_bindings.find((b) => b.type === "rfc3161-tst").proof;
const BARE_TOKEN_DER = Buffer.from(BARE_TOKEN_B64, "base64");
// The fixture's messageImprint is over the fixture artifact's own execution_hash, not our
// synthetic HASH_HEX — the tests below only assert the WRAPPER-UNWRAP shape (stored der ==
// bare token, granted vs rejected classification), not a fresh F11 digest-binding check.
const FIXTURE_HASH_HEX = extractMessageImprintHex(BARE_TOKEN_B64);

function wrapGranted(tokenDer) {
  // TimeStampResp = SEQUENCE { status PKIStatusInfo ::= SEQUENCE { status INTEGER(0) }, timeStampToken }
  return derSeq(derSeq(derInt(0)), tokenDer);
}

function wrapRejected(status, reasonText) {
  const statusInfo = reasonText
    ? derSeq(derInt(status), derSeq(derEncUtf8(reasonText)))
    : derSeq(derInt(status));
  return derSeq(statusInfo);
}

// _anchor-testutil.mjs exports derEnc(tag, content) but not a UTF8String helper directly.
function derEncUtf8(text) {
  return derEnc(0x0c, Buffer.from(text, "utf8"));
}

test("anchorRfc3161: unwraps a granted TimeStampResp — stored der is the bare token, not the wrapper", async () => {
  const wrapped = wrapGranted(BARE_TOKEN_DER);
  assert.notEqual(wrapped[0], 0x06, "sanity: the wrapper's first child must NOT be an OID (else this test isn't exercising the wrapper path)");
  const fetchImpl = async () => ({
    ok: true,
    headers: { get: () => "application/timestamp-reply" },
    arrayBuffer: async () => wrapped.buffer.slice(wrapped.byteOffset, wrapped.byteOffset + wrapped.byteLength),
  });
  const anchor = await anchorRfc3161(FIXTURE_HASH_HEX, { ca: "freetsa", fetchImpl });
  const storedDer = Buffer.from(anchor.der, "base64");
  assert.ok(storedDer.equals(BARE_TOKEN_DER), "stored der must be the unwrapped bare token, byte-identical to the fixture's bare-token shape");
  // Round-trips through the SAME strict vendored verifier a real checkpoint anchor is checked against.
  const verified = verifyRfc3161({ proof: anchor.der }, { rootPem: FREETSA_ROOT_PEM, expectHashHex: FIXTURE_HASH_HEX });
  assert.ok(verified.serial, "verifyRfc3161 must succeed against the unwrapped der — this is the check that was broken in production");
});

test("anchorRfc3161: an already-bare ContentInfo (fixture/back-compat shape) still passes through untouched", async () => {
  const fetchImpl = async () => ({
    ok: true,
    headers: { get: () => "application/timestamp-reply" },
    arrayBuffer: async () => BARE_TOKEN_DER.buffer.slice(BARE_TOKEN_DER.byteOffset, BARE_TOKEN_DER.byteOffset + BARE_TOKEN_DER.byteLength),
  });
  const anchor = await anchorRfc3161(FIXTURE_HASH_HEX, { ca: "freetsa", fetchImpl });
  assert.ok(Buffer.from(anchor.der, "base64").equals(BARE_TOKEN_DER));
});

test("anchorForCheckpoint: non-granted PKIStatus is a relay_error queue marker, never an aborted checkpoint", async () => {
  const rejected = wrapRejected(2, "Bad request format or system error.");
  const fetchImpl = async () => ({
    ok: true,
    headers: { get: () => "application/timestamp-reply" },
    arrayBuffer: async () => rejected.buffer.slice(rejected.byteOffset, rejected.byteOffset + rejected.byteLength),
  });
  const { anchor, queueMarker } = await anchorForCheckpoint(HASH_HEX, { checkpointSeq: 7, fetchImpl });
  assert.equal(anchor, undefined, "a TSA rejection must never surface as a successful anchor");
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_error");
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA_REF, queueMarker), []);
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
