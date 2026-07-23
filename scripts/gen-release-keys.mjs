#!/usr/bin/env node
// One-time (or rotation) generator for the release signing keypair (HELM-H8).
// Writes the PUBLIC half to schema/release-signing-keys.json (commit it) and
// prints the PRIVATE half's base64 blob to stdout — pipe that directly into
// `gh secret set HELM_RELEASE_SIGNING_KEY_B64`, never write it to a file.
import { writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeys, serializeKeys } from "../hub/keys.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "schema", "release-signing-keys.json");

const keys = generateKeys();
const serialized = serializeKeys(keys);

writeFileSync(
  OUT,
  JSON.stringify({ ed25519: { publicKey: serialized.ed25519.publicKey }, mldsa44: { publicKey: serialized.mldsa44.publicKey } }, null, 2) + "\n"
);

console.log(`wrote public keys -> ${OUT}`);
console.log("");
console.log("SECRET (do not commit) — set as HELM_RELEASE_SIGNING_KEY_B64:");
console.log(Buffer.from(JSON.stringify(serialized)).toString("base64"));
