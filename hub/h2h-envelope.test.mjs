// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// BILAT-H2H-ENVELOPE-1 conformance vectors (BILAT-H2H-BUILD-SPEC.md §6):
// a two-fixture round-trip — (1) valid round-trip, Org A produces, Org B's
// reference verifier ingests and accepts; (2) tamper/version-mismatch
// rejection — both fail closed, never a partial ingest.
import { test } from "node:test";
import assert from "node:assert/strict";

const { generateKeys, publicKeysOf } = await import("./keys.mjs");
const { buildStatement, emitEnvelope } = await import("./envelope.mjs");
const { exportH2HEnvelope, importH2HEnvelope, H2H_ENVELOPE_VERSION, H2H_PREDICATE_TYPE, KNOWN_PAYLOAD_TYPES } =
  await import("./h2h-envelope.mjs");

// Two independently-operated Helms — Org A signs, Org B verifies against
// Org A's public keys it already holds out of band (spec §2.2). Never a
// shared key, never a network round-trip to fetch one.
const orgAKeys = generateKeys();
const orgAPublicKeys = publicKeysOf(orgAKeys);

function csrPayload() {
  return {
    record_type: "counter_signed_receipt",
    kernel_pin: "art-575",
    note: "both parties recomputed and signed the same result",
  };
}

test("fixture 1 — valid round-trip: Org A produces, Org B ingests and accepts", () => {
  const envelope = exportH2HEnvelope(
    { senderOrgId: "did:key:orgA", payloadType: "counter_signed_receipt", payload: csrPayload() },
    orgAKeys
  );

  // This is what actually leaves Org A's machine over whatever transport the
  // two orgs picked (email/SFTP/USB/etc.) — a plain JSON-serializable object.
  const wireBytes = JSON.stringify(envelope);
  const received = JSON.parse(wireBytes);

  const result = importH2HEnvelope(received, orgAPublicKeys);
  assert.equal(result.ok, true);
  assert.equal(result.senderOrgId, "did:key:orgA");
  assert.equal(result.payloadType, "counter_signed_receipt");
  assert.deepEqual(result.payload, csrPayload());
});

test("fixture 2a — tamper rejection: flipped signature byte fails closed, no partial ingest", () => {
  const envelope = exportH2HEnvelope(
    { senderOrgId: "did:key:orgA", payloadType: "counter_signed_receipt", payload: csrPayload() },
    orgAKeys
  );
  const tampered = {
    ...envelope,
    signatures: envelope.signatures.map((s) =>
      s.alg === "EdDSA" ? { ...s, sig: Buffer.from("not a real signature bytes!!").toString("base64") } : s
    ),
  };

  const result = importH2HEnvelope(tampered, orgAPublicKeys);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "signature");
  assert.equal(result.payload, undefined, "a rejected envelope must never surface a partial payload");
});

test("fixture 2b — version-mismatch rejection: unrecognized wire version fails closed with the exact §5 message", () => {
  // A genuinely signed envelope (not a forgery) carrying a wire version this
  // importer does not recognize — isolates the version-negotiation path from
  // the signature-tamper path fixture 2a already covers.
  const statement = buildStatement({
    subject: [{ name: "did:key:orgA", digest: {} }],
    predicateType: H2H_PREDICATE_TYPE,
    predicate: {
      version: "helm-h2h-envelope@99",
      sender_org_id: "did:key:orgA",
      payload_type: "counter_signed_receipt",
      payload: csrPayload(),
    },
  });
  const futureVersionEnvelope = emitEnvelope(statement, orgAKeys);

  const result = importH2HEnvelope(futureVersionEnvelope, orgAPublicKeys);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "version");
  assert.equal(
    result.message,
    "Received an envelope in a format this Helm doesn't understand (wire vhelm-h2h-envelope@99, payload counter_signed_receipt) — ask the sender which Helm version they're running."
  );
  assert.equal(result.payload, undefined, "a rejected envelope must never surface a partial payload");
});

test("unrecognized payload_type also fails closed at import (predicate carries an unknown kind)", () => {
  const statement = buildStatement({
    subject: [{ name: "did:key:orgA", digest: {} }],
    predicateType: H2H_PREDICATE_TYPE,
    predicate: {
      version: H2H_ENVELOPE_VERSION,
      sender_org_id: "did:key:orgA",
      payload_type: "smuggled_run_input",
      payload: { note: "should never be accepted" },
    },
  });
  const envelope = emitEnvelope(statement, orgAKeys);

  const result = importH2HEnvelope(envelope, orgAPublicKeys);
  assert.equal(result.ok, false);
  assert.equal(result.reason, "payload_type");
});

test("known payload_type round-trips for each of the three cited artifact shapes", () => {
  for (const payloadType of KNOWN_PAYLOAD_TYPES) {
    const envelope = exportH2HEnvelope({ senderOrgId: "did:key:orgA", payloadType, payload: { note: payloadType } }, orgAKeys);
    const result = importH2HEnvelope(envelope, orgAPublicKeys);
    assert.equal(result.ok, true, `${payloadType} should round-trip`);
    assert.equal(result.payloadType, payloadType);
  }
});

test("KNOWN_PAYLOAD_TYPES matches the spec's three cited artifact shapes (§2.1)", () => {
  assert.deepEqual([...KNOWN_PAYLOAD_TYPES].sort(), ["cosigned_checkpoint_head", "counter_signed_receipt", "matter_bundle"]);
});

test("exportH2HEnvelope refuses to emit an envelope for an unrecognized payload_type", () => {
  assert.throws(
    () => exportH2HEnvelope({ senderOrgId: "did:key:orgA", payloadType: "run_input", payload: {} }, orgAKeys),
    /unknown payload_type/
  );
});

test("H2H_ENVELOPE_VERSION is the fixed const the schema pins", () => {
  assert.equal(H2H_ENVELOPE_VERSION, "helm-h2h-envelope@1");
});

test("run-input asymmetry: the export/import contract never names a 'run' or 'execute' shape (spec §4)", () => {
  for (const t of KNOWN_PAYLOAD_TYPES) {
    assert.doesNotMatch(t, /run|execute|job/);
  }
});
