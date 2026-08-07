// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELIOS-RECEIPT-1: the deliverable IS this test, not the copy — it exists
// to stop the §5 honest phrase from drifting into an unconditional claim
// the next time someone edits helios-receipt.mjs.
import { test } from "node:test";
import assert from "node:assert/strict";
import { formatHeliosReceipt, FORBIDDEN_OVERCLAIMS } from "./helios-receipt.mjs";

test("formatHeliosReceipt: names the trust model and the pinned client version", () => {
  const phrase = formatHeliosReceipt({ block: 21000000 });
  assert.match(phrase, /sync-committee trust model/);
  assert.match(phrase, /Helios `0\.11\.1`/);
  assert.match(phrase, /as of block `21000000`/);
  assert.match(phrase, /not a full-node verification/);
});

test("formatHeliosReceipt: block is required", () => {
  assert.throws(() => formatHeliosReceipt({}), /block is required/);
});

for (const overclaim of FORBIDDEN_OVERCLAIMS) {
  test(`formatHeliosReceipt: never collapses to "${overclaim}"`, () => {
    const phrase = formatHeliosReceipt({ block: 21000000 }).toLowerCase();
    assert.ok(
      !phrase.includes(overclaim.toLowerCase()),
      `receipt phrase must never contain the overclaim "${overclaim}"`,
    );
  });
}

test("formatHeliosReceipt: never asserts unconditional verification against 'the chain'", () => {
  const phrase = formatHeliosReceipt({ block: 21000000 });
  // The only occurrence of "chain" allowed is inside "full-node verification"
  // qualifier text (there is none) — a bare "verified... chain" or
  // "verified against the chain" phrasing is exactly what §5 forbids.
  assert.doesNotMatch(phrase, /verified (against|on)( the)? chain/i);
});
