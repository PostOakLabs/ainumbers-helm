// Live round-trip fixture against the SHIPPED Anchor Suite relay + a public
// OTS calendar (§4 HELM-H3 "done": anchor round-trip tests green). One CA and
// one calendar only — the relay's own rate-limit rule is 50 req/10s per IP
// (memory: project-ainumbers-cloudflare-housekeeping-2026-07-11), a single
// call per run never approaches it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { anchorRfc3161, anchorOpenTimestamps, RELAY_CA_LIST, OTS_CALENDAR_LIST } from "./anchor-client.mjs";

function digestOf(text) {
  return createHash("sha256").update(text).digest("hex");
}

test("anchor round-trip: rfc3161 relay returns a verifiable-shaped TimeStampResp", { timeout: 40_000 }, async () => {
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

test("anchor round-trip: opentimestamps calendar returns a pending attestation", { timeout: 25_000 }, async () => {
  const hash = digestOf(`helm-h3-ots-fixture-${Date.now()}`);
  const anchor = await anchorOpenTimestamps(hash, { calendar: OTS_CALENDAR_LIST[0] });
  assert.equal(anchor.type, "opentimestamps");
  assert.equal(anchor.anchored_hash, `sha256:${hash}`);
  assert.equal(anchor.upgraded, false);
  assert.ok(Buffer.from(anchor.pending_proof, "base64").length > 0);
});
