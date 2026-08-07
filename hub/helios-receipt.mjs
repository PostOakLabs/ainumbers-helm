// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// HELIOS-RECEIPT-1: the ONE place any surface consuming a Helios-verified
// balance/storage value must format that claim through. A light client
// proves a value against a pinned checkpoint (sync-committee signatures),
// not against "the chain" — research/HELIOS-SCOPE-2026-08-06.md §5 drafted
// this exact phrasing so the honest version, not the tempting short one,
// is what ships. No call-firing code exists yet (HELIOS-CONFIG-1 left the
// sidecar unwired) — this module is the surface in waiting so the phrase
// is fixed before any consumer is built, not retrofitted after.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const VENDOR_CONFIG_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "scripts",
  "helios-vendor.config.json",
);

// Cached at module load — the pinned tag is a build-time fact (re-vendoring
// bumps this file), not a per-call one.
const PINNED_HELIOS_VERSION = JSON.parse(readFileSync(VENDOR_CONFIG_PATH, "utf8")).pinnedTag;

/**
 * Format the honest Helios light-client receipt phrase for a verified
 * balance/storage value. §5's drafted template, verbatim.
 * @param {{block: string|number}} args
 * @returns {string}
 */
export function formatHeliosReceipt({ block }) {
  if (block === undefined || block === null || block === "") {
    throw new Error("formatHeliosReceipt: block is required");
  }
  return (
    `Balance/storage value verified via Ethereum light-client protocol ` +
    `(sync-committee trust model, Helios \`${PINNED_HELIOS_VERSION}\`) as of block \`${block}\` ` +
    `— not a full-node verification.`
  );
}

// Phrases the receipt must never collapse into — checked by
// helios-receipt.test.mjs so a future edit can't silently overclaim.
export const FORBIDDEN_OVERCLAIMS = [
  "verified against the chain",
  "on-chain confirmed",
  "trustless",
];
