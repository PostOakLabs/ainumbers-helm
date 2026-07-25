// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Pin-freshness gate for ../vendored/tsa-roots.mjs (HELM-TSA-1, STANDING-ORDERS
// #0: "pinned roots are data that goes stale — no human duty"). Runs under
// `node scripts/test.mjs` (already wired into CI, ci.yml's `run: node
// scripts/test.mjs` steps) — no separate script or workflow edit needed. Derives
// staleness from each pin's OWN `notAfter` field; nobody has to remember to
// re-check a calendar.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PINNED_TSA_ROOTS } from "./../vendored/tsa-roots.mjs";

// A TSA root is typically valid 15-20+ years; 180 days' notice before expiry is
// ample runway to re-pin (see tsa-roots.mjs's header for the re-pin recipe) while
// still being "this will actually go red before it's a problem," not decades-early
// noise.
const WARN_WINDOW_DAYS = 180;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

test("PINNED_TSA_ROOTS: every pin's notAfter is well-formed and not past", () => {
  for (const root of PINNED_TSA_ROOTS) {
    const notAfter = new Date(root.notAfter);
    assert.ok(!Number.isNaN(notAfter.getTime()), `${root.name}: notAfter "${root.notAfter}" does not parse`);
    assert.ok(notAfter.getTime() > Date.now(), `${root.name}: pinned root has EXPIRED (notAfter=${root.notAfter}) — re-pin per tsa-roots.mjs's header recipe, remove the expired pin`);
  }
});

test(`PINNED_TSA_ROOTS: no pin expires within ${WARN_WINDOW_DAYS} days (re-pin runway)`, () => {
  const soon = [];
  for (const root of PINNED_TSA_ROOTS) {
    const daysLeft = (new Date(root.notAfter).getTime() - Date.now()) / MS_PER_DAY;
    if (daysLeft < WARN_WINDOW_DAYS) soon.push(`${root.name} (${Math.floor(daysLeft)}d left, notAfter=${root.notAfter})`);
  }
  assert.deepEqual(soon, [], `pin(s) expiring within ${WARN_WINDOW_DAYS} days — re-pin per tsa-roots.mjs's header recipe:\n  ${soon.join("\n  ")}`);
});

test("PINNED_TSA_ROOTS: notAfter in the data file matches the certificate's own ASN.1 validity field", async () => {
  const { pkijs, asn1js } = await import("../vendored/pkijs.bundle.mjs");
  for (const root of PINNED_TSA_ROOTS) {
    const b64 = root.pem.replace(/-----BEGIN CERTIFICATE-----/, "").replace(/-----END CERTIFICATE-----/, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const asn1 = asn1js.fromBER(der.buffer);
    const cert = new pkijs.Certificate({ schema: asn1.result });
    assert.equal(cert.notAfter.value.toISOString(), new Date(root.notAfter).toISOString(), `${root.name}: notAfter field drifted from the certificate's real ASN.1 validity — fix the data file, not the cert`);
    assert.equal(cert.notBefore.value.toISOString(), new Date(root.notBefore).toISOString(), `${root.name}: notBefore field drifted from the certificate's real ASN.1 validity — fix the data file, not the cert`);
  }
});
