// Tests for the browser-mode anchor client (HELM-P3-A5; P3-D4). Covers the
// three paths the row's done-criteria name: anchored, queued/skipped, and
// fully-offline — plus a tampered-TST-rejected case, all with a fake
// fetchImpl (zero real network — that's what fetchImpl injection is for).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { submitAnchor, buildQueueMarker, RELAY_CAS } from "./anchor-browser.mjs";
import { verifyAnchorBinding } from "./verify-bundle.mjs";
import { validate } from "../vendored/schema-validator.mjs";
import ANCHOR_QUEUE_MARKER_SCHEMA from "../vendored/schemas/anchor_queue_marker.schema.mjs";
import { derSequence, derInteger, derOid, derNull, derOctetString, derSet, derExplicit, derGeneralizedTime, hexToBytes, bytesToBase64 } from "../vendored/der-encode.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(HERE, "../../fixtures/anchor_queue_marker");

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TSTINFO = "1.2.840.113549.1.9.16.1.4";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

const HASH_HEX = "af2c0d0db5baec3e06592c51e073a7606955a005fe70bbbce5c0f85c08fe2f0b";

// Builds a minimal-but-structurally-real RFC 3161 TimeStampToken (CMS
// SignedData wrapping TSTInfo) bound to whatever hash is passed in — enough
// for ../vendored/der.mjs's parseRfc3161MessageImprint to walk successfully.
// No signature/cert material: this module only claims to check structural
// binding (see der.mjs's header), so a fake token with no real signature is
// exactly what a "the relay is untrusted" test needs.
function fakeTokenB64(hashHexToBind, { genTime = "20260101000000Z" } = {}) {
  const messageImprint = derSequence(derSequence(derOid(OID_SHA256), derNull()), derOctetString(hexToBytes(hashHexToBind)));
  const tstInfo = derSequence(
    derInteger(new Uint8Array([1])),
    derOid("1.2.3.4"),
    messageImprint,
    derInteger(new Uint8Array([1])),
    derGeneralizedTime(genTime)
  );
  const encapContentInfo = derSequence(derOid(OID_TSTINFO), derExplicit(0, derOctetString(tstInfo)));
  const signedData = derSequence(derInteger(new Uint8Array([3])), derSet(), encapContentInfo);
  const contentInfo = derSequence(derOid(OID_SIGNED_DATA), derExplicit(0, signedData));
  return bytesToBase64(contentInfo);
}

function fakeResponse(b64, { ok = true, status = 200, contentType = "application/timestamp-reply" } = {}) {
  const bytes = Uint8Array.from(Buffer.from(b64, "base64"));
  return {
    ok,
    status,
    headers: { get: (name) => (name === "Content-Type" ? contentType : null) },
    arrayBuffer: async () => bytes.buffer,
  };
}

test("submitAnchor: relay returns a token bound to our hash — accepted and verifiable", async () => {
  const b64 = fakeTokenB64(HASH_HEX);
  const fetchImpl = async () => fakeResponse(b64);
  const { anchor, queueMarker } = await submitAnchor(HASH_HEX, { checkpointSeq: 5, ca: "freetsa", fetchImpl });
  assert.equal(queueMarker, undefined);
  assert.equal(anchor.type, "rfc3161");
  assert.equal(anchor.anchored_hash, `sha256:${HASH_HEX}`);
  const binding = verifyAnchorBinding(anchor, HASH_HEX);
  assert.equal(binding.checked, true);
  assert.equal(binding.bound, true);
});

test("submitAnchor: relay unreachable (network throw) — queued, never silent", async () => {
  const fetchImpl = async () => { throw new Error("ECONNREFUSED"); };
  const { anchor, queueMarker } = await submitAnchor(HASH_HEX, { checkpointSeq: 5, fetchImpl });
  assert.equal(anchor, undefined);
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_unreachable");
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA, queueMarker), []);
});

test("submitAnchor: relay HTTP error — queued with relay_error, not silently dropped", async () => {
  const fetchImpl = async () => ({ ok: false, status: 503, headers: { get: () => null }, arrayBuffer: async () => new ArrayBuffer(0) });
  const { queueMarker } = await submitAnchor(HASH_HEX, { checkpointSeq: 5, fetchImpl });
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_error");
});

test("submitAnchor: relay returns a token bound to a DIFFERENT hash — tampered/mismatched TST rejected, not accepted as an anchor", async () => {
  const wrongHash = "0000000000000000000000000000000000000000000000000000000000000000";
  const b64 = fakeTokenB64(wrongHash);
  const fetchImpl = async () => fakeResponse(b64);
  const { anchor, queueMarker } = await submitAnchor(HASH_HEX, { checkpointSeq: 5, fetchImpl });
  assert.equal(anchor, undefined);
  assert.equal(queueMarker.status, "queued");
  assert.equal(queueMarker.reason, "relay_error");
});

test("submitAnchor: offline (zero-egress) — no network call at all, skipped marker recorded", async () => {
  let called = false;
  const fetchImpl = async () => { called = true; return fakeResponse(fakeTokenB64(HASH_HEX)); };
  const { anchor, queueMarker } = await submitAnchor(HASH_HEX, { checkpointSeq: 5, offline: true, fetchImpl });
  assert.equal(called, false, "offline mode must never touch the network");
  assert.equal(anchor, undefined);
  assert.equal(queueMarker.status, "skipped");
  assert.equal(queueMarker.reason, "egress_blocked");
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA, queueMarker), []);
});

test("buildQueueMarker: rejects a shape that would fail the schema (e.g. bad status)", () => {
  assert.throws(() => buildQueueMarker({ checkpointSeq: 1, status: "anchored", reason: "egress_blocked", relayUrl: "https://anchor.ainumbers.co/relay/freetsa" }));
});

test("RELAY_CAS matches the shipped relay's supported CA set", () => {
  assert.deepEqual(RELAY_CAS, ["digicert", "sectigo", "freetsa"]);
});

test("fixture: golden anchor_queue_marker validates against the schema", () => {
  const golden = JSON.parse(readFileSync(join(FIXTURES, "golden.json"), "utf8"));
  assert.deepEqual(validate(ANCHOR_QUEUE_MARKER_SCHEMA, golden), []);
});

test("fixture: tampered anchor_queue_marker (status not in enum) fails the schema", () => {
  const tampered = JSON.parse(readFileSync(join(FIXTURES, "tampered.json"), "utf8"));
  const errs = validate(ANCHOR_QUEUE_MARKER_SCHEMA, tampered);
  assert.ok(errs.length > 0);
});
