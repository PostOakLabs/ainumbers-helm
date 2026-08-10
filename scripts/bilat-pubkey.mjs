#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// BILAT-H2H-CLI-1: `helmd bilat-pubkey [--json]` — prints THIS Helm's own
// public keys in the shareable format a counterparty org needs to later
// `bilat-import` an envelope this org exports. There is no peer directory
// (BILAT-H2H-BUILD-SPEC.md §2.2 — out of band, by design): a real exchange
// looks like "run this, send the one-line JSON to your counterparty over
// whatever channel you already trust them on, they save it as
// peer-orgA-keys.json". No daemon required — reads the same
// ~/.helm/keys.enc.json every other offline Helm command reads.
import { loadOrCreateKeys, publicKeysOf } from "../hub/keys.mjs";

function usage() {
  console.error(`usage: helmd bilat-pubkey [--json]

Prints this Helm's own public keys in the format bilat-import expects for a
--peer-keys file: { ed25519SpkiB64, mldsa44B64 }. Hand the output to a
counterparty over whatever channel you already trust them on (email, a call,
a shared doc) — Helm keeps no peer directory of its own by design.`);
}

const rawArgs = process.argv.slice(2);
if (rawArgs.includes("-h") || rawArgs.includes("--help")) {
  usage();
  process.exit(0);
}
const jsonMode = rawArgs.includes("--json");

const keys = loadOrCreateKeys();
const pub = publicKeysOf(keys);
const shareable = {
  ed25519SpkiB64: pub.ed25519.export({ format: "der", type: "spki" }).toString("base64"),
  mldsa44B64: Buffer.from(pub.mldsa44).toString("base64"),
};

if (jsonMode) {
  console.log(JSON.stringify(shareable));
} else {
  console.log(JSON.stringify(shareable, null, 2));
}
