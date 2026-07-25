// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-TSA-1 done-criteria, proven 100% OFFLINE against real, previously-captured
// TimeStampResp bytes (../fixtures/rfc3161-verify-fixtures.mjs) — no network in
// this file. A tampered signature and an untrusted root each fail closed; a
// correct token from two different real TSAs (FreeTSA, Sectigo) fully verifies.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyRfc3161Full } from "./rfc3161-verify.mjs";
import { FREETSA_TOKEN_B64, SECTIGO_TOKEN_B64, EXPECTED_HASH_HEX } from "../fixtures/rfc3161-verify-fixtures.mjs";
import { PINNED_TSA_ROOTS } from "../vendored/tsa-roots.mjs";

function flipByteNearEnd(b64, offsetFromEnd) {
  const bin = Buffer.from(b64, "base64");
  const copy = Buffer.from(bin);
  copy[copy.length - offsetFromEnd] ^= 0xff;
  return copy.toString("base64");
}

test("verifyRfc3161Full: genuine FreeTSA token — all four checks pass", async () => {
  const r = await verifyRfc3161Full(FREETSA_TOKEN_B64, EXPECTED_HASH_HEX);
  assert.equal(r.messageImprint.bound, true);
  assert.equal(r.signature.valid, true);
  assert.equal(r.chain.valid, true);
  assert.equal(r.chain.rootName, "FreeTSA Root CA");
  assert.equal(r.validity.valid, true);
});

test("verifyRfc3161Full: genuine Sectigo token — all four checks pass, different root", async () => {
  const r = await verifyRfc3161Full(SECTIGO_TOKEN_B64, EXPECTED_HASH_HEX);
  assert.equal(r.messageImprint.bound, true);
  assert.equal(r.signature.valid, true);
  assert.equal(r.chain.valid, true);
  assert.equal(r.chain.rootName, "Sectigo Public Time Stamping Root R46");
  assert.equal(r.validity.valid, true);
});

test("verifyRfc3161Full: FAILS CLOSED on a tampered signature (bit flip near the CMS signature bytes)", async () => {
  const tampered = flipByteNearEnd(FREETSA_TOKEN_B64, 50);
  const r = await verifyRfc3161Full(tampered, EXPECTED_HASH_HEX);
  // messageImprint lives earlier in the structure and is untouched by a tail
  // bit-flip — proves the four checks are genuinely independent, not one
  // umbrella verdict.
  assert.equal(r.messageImprint.bound, true);
  assert.equal(r.signature.valid, false);
  assert.ok(r.signature.reason, "must explain why it failed");
});

test("verifyRfc3161Full: FAILS CLOSED when messageImprint does not bind to the anchored digest", async () => {
  const r = await verifyRfc3161Full(FREETSA_TOKEN_B64, "ff".repeat(32));
  assert.equal(r.messageImprint.bound, false);
  assert.equal(r.signature.checked, false, "not worth spending the crypto pass on an unbound token");
  assert.equal(r.chain.checked, false);
  assert.equal(r.validity.checked, false);
});

test("verifyRfc3161Full: FAILS CLOSED — untrusted-root token (genuine signature, but its root is not pinned)", async () => {
  const noFreetsa = PINNED_TSA_ROOTS.filter((root) => root.ca !== "freetsa");
  const r = await verifyRfc3161Full(FREETSA_TOKEN_B64, EXPECTED_HASH_HEX, { pinnedRoots: noFreetsa });
  // The signature itself is genuine — this proves chain-to-root is a DISTINCT
  // gate from signature validity, exactly the R15-F10 gap this WU closes (a
  // hostile relay's forged token would fail signature; a genuine token signed by
  // a real but non-pinned CA fails HERE instead, and must still fail closed).
  assert.equal(r.signature.valid, true);
  assert.equal(r.chain.valid, false);
  assert.ok(r.chain.reason, "must explain why it failed");
});

test("verifyRfc3161Full: malformed input fails closed on all four checks, never throws", async () => {
  const r = await verifyRfc3161Full(Buffer.from("not cms der").toString("base64"), EXPECTED_HASH_HEX);
  assert.equal(r.messageImprint.bound, false);
  assert.equal(r.signature.valid, false);
  assert.equal(r.chain.valid, false);
  assert.equal(r.validity.valid, false);
});
