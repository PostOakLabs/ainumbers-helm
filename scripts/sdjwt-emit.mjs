#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-SDJWT-EMIT-1: `helmd emit-sdjwt` — mint an SD-JWT (RFC 9901) from a
// claims file, entirely offline, no daemon required. EMISSION ONLY: this
// prints/writes the compact token plus an emission record; it never submits
// the credential anywhere and integrates no wallet.
//
// Maturity labels travel with the output: the base layer is RFC 9901
// (ratified); when --profile vc is used the record and the human output both
// label the VC layer "tracks draft" (draft-ietf-oauth-sd-jwt-vc-19, IESG
// Last Call at pin time) — it is NOT a ratified RFC.
//
// Keys: caller-supplied PEM files (Ed25519). Daemon keystore integration is
// deliberately out of scope here.
//
// Salt seed: pass --seed <hex> to make the emission reproducible (the seed
// drives an HMAC-SHA256-CTR salt stream); without it the token still emits
// but the record says reproducible:false. A seeded record is ISSUER-PRIVATE:
// the seed re-derives every disclosure salt, so never publish the seed
// beside the token.
import { readFileSync, writeFileSync } from "node:fs";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { ed25519Signer, ed25519Verifier, emitSdJwt, verifySdJwt } from "../hub/sdjwt-emit.mjs";

function usage() {
  console.error(`usage: helmd emit-sdjwt --claims <claims.json> --frame <frame.json> --key <private.pem>
                         [--profile base|vc] [--vct <uri>] [--kid <kid>] [--hash <alg>]
                         [--seed <hex>] [--seed-out <file>] [--out <token.txt>]
                         [--record <record.json>] [--json]
       helmd emit-sdjwt --verify <token.txt> --public-key <public.pem> [--json]

Emits an SD-JWT (RFC 9901) from a claims JSON file, entirely offline.
  --claims   JSON object of credential claims (iat/iss included when wanted)
  --frame    disclosure frame, e.g. {"_sd": ["claim_a", "claim_b"]} — optional
  --key      Ed25519 private key PEM (signing)
  --profile  "base" (default) emits plain RFC 9901 SD-JWT; "vc" adds the
             SD-JWT VC profile layer (typ dc+sd-jwt, requires vct). THE VC
             LAYER TRACKS A DRAFT (draft-ietf-oauth-sd-jwt-vc-19, IESG Last
             Call at pin time) and is labelled "tracks draft" in the emission
             record; it is not a ratified RFC.
  --seed     hex seed for a reproducible salt stream; the emission record
             then carries it marked issuer-private (re-derives every
             disclosure salt — never publish it beside the token)
  --seed-out also write the salt-seed record to this file
  --verify   verify a compact SD-JWT against --public-key and print the
             recovered claims; works on full and presented tokens

Exit codes: 0 success, 1 verification/emit failure, 2 usage error.`);
}

function fail(msg) {
  console.error(`emit-sdjwt: ${msg}`);
  process.exit(2);
}

function argValue(args, flag) {
  const i = args.indexOf(flag);
  if (i === -1) return undefined;
  if (i + 1 >= args.length) fail(`missing value after ${flag}`);
  return args[i + 1];
}

const args = process.argv.slice(2);
if (args.includes("-h") || args.includes("--help") || args.length === 0) {
  usage();
  process.exit(args.length === 0 ? 2 : 0);
}
const jsonMode = args.includes("--json");

try {
  const verifyPath = argValue(args, "--verify");
  if (verifyPath) {
    const pubPem = argValue(args, "--public-key");
    if (!pubPem) fail("--verify requires --public-key <public.pem>");
    const token = readFileSync(verifyPath, "utf8").trim();
    const publicKey = createPublicKey(readFileSync(pubPem, "utf8"));
    try {
      const { payload, header } = await verifySdJwt(token, { verifier: ed25519Verifier(publicKey) });
      if (jsonMode) {
        console.log(JSON.stringify({ valid: true, header, payload }));
      } else {
        console.log("valid: true");
        console.log(`header: ${JSON.stringify(header)}`);
        console.log(`claims: ${JSON.stringify(payload, null, 2)}`);
      }
      process.exit(0);
    } catch (err) {
      if (jsonMode) console.log(JSON.stringify({ valid: false, error: String(err.message ?? err) }));
      else console.error(`emit-sdjwt: verification FAILED: ${err.message ?? err}`);
      process.exit(1);
    }
  }

  const claimsPath = argValue(args, "--claims");
  const keyPem = argValue(args, "--key");
  if (!claimsPath || !keyPem) fail("--claims and --key are required (or use --verify)");

  const claims = JSON.parse(readFileSync(claimsPath, "utf8"));
  const framePath = argValue(args, "--frame");
  const disclosureFrame = framePath ? JSON.parse(readFileSync(framePath, "utf8")) : undefined;
  const profile = argValue(args, "--profile") ?? "base";
  const vct = argValue(args, "--vct");
  if (vct != null) claims.vct = vct;
  const kid = argValue(args, "--kid");
  const hashAlg = argValue(args, "--hash") ?? "sha-256";
  const seedHex = argValue(args, "--seed");

  const privateKey = createPrivateKey(readFileSync(keyPem, "utf8"));
  const { token, record } = await emitSdJwt({
    claims,
    disclosureFrame,
    profile,
    seedHex,
    signer: ed25519Signer(privateKey),
    kid,
    hashAlg,
  });

  const outPath = argValue(args, "--out");
  if (outPath) writeFileSync(outPath, token + "\n");
  const recordPath = argValue(args, "--record");
  if (recordPath) writeFileSync(recordPath, JSON.stringify(record, null, 2) + "\n");
  const seedOutPath = argValue(args, "--seed-out");
  if (seedOutPath) writeFileSync(seedOutPath, JSON.stringify(record.saltSeed, null, 2) + "\n");

  if (jsonMode) {
    console.log(JSON.stringify({ token, record }));
  } else {
    console.log(token);
    console.error(
      [
        `profile: ${record.profile.key}${record.profile.spec ? ` (${record.profile.spec})` : record.profile.tracks ? ` (tracks ${record.profile.tracks})` : ""}`,
        `status: ${record.profile.status}`,
        `reproducible: ${record.reproducible}${record.reproducible ? " (seed recorded — issuer-private, do not publish beside the token)" : " (no seed given)"}`,
        outPath ? `token written: ${outPath}` : "token on stdout above",
        recordPath ? `record written: ${recordPath}` : null,
      ]
        .filter(Boolean)
        .join("\n")
    );
  }
  process.exit(0);
} catch (err) {
  console.error(`emit-sdjwt: ${err.message ?? err}`);
  process.exit(1);
}
