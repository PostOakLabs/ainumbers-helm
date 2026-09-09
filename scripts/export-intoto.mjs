#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-INTOTO-EXPORT-1: `helmd export-intoto <bundle.json> [--out statement.json]`
// wraps a Helm evidence bundle's digest-level record as an in-toto Statement
// v1 with the registered predicate type `https://ainumbers.co/attestation/
// helm-run/v1`, then wraps that statement in the SAME dual-signature DSSE
// envelope every Helm object already gets (hub/envelope.mjs — Ed25519 MUST +
// ML-DSA-44 SHOULD, RFC 9964 algorithm identifiers, PAE framing untouched).
// // The signature file is what platform teams gate on with the policy engines
// they already run (cosign verify-attestation, Kyverno, gh attestation
// verify — see docs/INTEROP-ATTESTATIONS.md).
//
// Thin and offline by construction: reads the bundle file, writes the
// statement file, zero network calls, no daemon required. Signing keys are
// this install's own at-rest keys via hub/keys.mjs loadOrCreateKeys() — the
// same key material `helmd bilat-export` signs with (and `helmd bilat-pubkey`
// prints for counterparty verification). Never touches hub/ sources, never
// adds a dependency (bin/zero-dep.test.mjs).
//
// Digest-level discipline: the predicate is built from the bundle's OWN
// already-sealed statements (the manifest predicate plus each object
// statement's predicate fields). It carries digests, ids, and trust labels —
// never raw payload bytes. Known-dangerous field names are refused outright,
// reusing the same refusal list hub/bundle.mjs enforces upstream, so a field
// that escaped redaction upstream can't leak through here silently.
import { basename } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { buildStatement, emitEnvelope } from "../hub/envelope.mjs";
import { loadOrCreateKeys } from "../hub/keys.mjs";
import { cgCanon } from "../hub/vendored/ocg/kernels/_hash.mjs";
import { validate } from "./lib/schema-validator.mjs";

export const HELM_RUN_PREDICATE_TYPE = "https://ainumbers.co/attestation/helm-run/v1";
export const EXIT = { OK: 0, EXPORT_FAILURE: 1, USAGE_ERROR: 2 };

// The predicate schema comes from the pinned schema file — validated
// against, never retyped inline (a retyped copy is how a schema and an
// exporter drift).
export const HELM_RUN_PREDICATE_SCHEMA = JSON.parse(
  readFileSync(new URL("../schema/predicates/helm-run-v1.schema.json", import.meta.url), "utf8")
);

// Same refusal list hub/bundle.mjs asserts against upstream — a digests-only
// exporter must never let a secret-shaped field through even if a hostile or
// buggy bundle carries one, because the predicate copies object fields.
const FORBIDDEN_FIELD_NAMES = new Set([
  "access_token", "refresh_token", "id_token", "secret", "secretKey", "privateKey",
  "password", "api_key", "raw_payload", "payload_bytes", "payload_body",
]);

// Recovers the in-toto statement from a sealed DSSE envelope — same read as
// hub/bundle.mjs's statementOf().
function statementOf(envelope) {
  return JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8"));
}

function assertNoForbiddenField(value, path = "$") {
  if (Array.isArray(value)) { value.forEach((v, i) => assertNoForbiddenField(v, `${path}[${i}]`)); return; }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      if (FORBIDDEN_FIELD_NAMES.has(k)) {
        return `${path}.${k}`;
      }
      const hit = assertNoForbiddenField(v, `${path}.${k}`);
      if (hit) return hit;
    }
  }
  return null;
}

// The three provenance fields only some bundle producers seal are copied
// first-found-wins from the object statements (and the manifest predicate),
// BUT only when every copy agrees: two different values for execution_hash
// means the bundle itself is self-inconsistent, and this exporter refuses to
// mint a statement that papers over that.
function provenanceFields(bundle) {
  const sources = (bundle.objects ?? [])
    .map((obj) => obj?.envelope && statementOf(obj.envelope))
    .filter(Boolean);
  sources.push(bundle.manifest?.envelope ? statementOf(bundle.manifest.envelope) : null);
  const out = {};
  for (const field of ["workflow_id", "execution_hash", "kernel_digest"]) {
    let value;
    for (const s of sources) {
      const v = s?.predicate?.[field];
      if (typeof v === "string" && v.length > 0) {
        if (value !== undefined && value !== v) {
          throw { exitCode: EXIT.EXPORT_FAILURE, message: `${field} is present with conflicting values (${value} vs ${v}) — bundle is self-inconsistent, export refused` };
        }
        value = v;
      }
    }
    if (value !== undefined) out[field] = value;
  }
  return out;
}

// Build the predicate from a bundle. Exported (not just internal) so the
// RED-then-GREEN test suite can unit-test the digest-level copy rules
// directly, not only through a full CLI spawn. Throws { exitCode, message }
// on any export failure. Returns { subject, predicate }.
export function buildHelmRunPredicate({ bundle, bundleSha256hex, bundleName }) {
  const manifestPredicate = bundle?.manifest?.predicate;
  if (!manifestPredicate || !Array.isArray(manifestPredicate.entries)) {
    throw { exitCode: EXIT.EXPORT_FAILURE, message: "bundle.manifest.predicate (or its entries[]) missing — not a Helm evidence bundle in the on-disk shape" };
  }

  const trustLabels = [...new Set(manifestPredicate.entries.map((e) => e.trust_label).filter(Boolean))].sort();

  const steps = [];
  for (const obj of bundle.objects ?? []) {
    const p = obj?.envelope ? statementOf(obj.envelope)?.predicate : null;
    if (!p) continue;
    const hit = assertNoForbiddenField(p);
    if (hit) throw { exitCode: EXIT.EXPORT_FAILURE, message: `${hit} looks like a secret/raw payload — export refused (digest-level only)` };
    if (typeof p.step_id === "string" && typeof p.output_digest === "string") {
      steps.push({ step_id: p.step_id, output_digest: p.output_digest });
    }
  }
  const manifestHit = assertNoForbiddenField(manifestPredicate);
  if (manifestHit) throw { exitCode: EXIT.EXPORT_FAILURE, message: `${manifestHit} looks like a secret/raw payload — export refused (digest-level only)` };

  const predicate = {
    run_id: manifestPredicate.run_id,
    ...provenanceFields(bundle),
    manifest_digest: manifestPredicate.workflow_manifest_digest,
    steps,
    trust_labels: trustLabels,
    bundle_sha256: `sha256:${bundleSha256hex}`,
  };

  const schemaErrors = validate(HELM_RUN_PREDICATE_SCHEMA, predicate);
  if (schemaErrors.length) {
    throw { exitCode: EXIT.EXPORT_FAILURE, message: `predicate fails the pinned schema — ${schemaErrors.join("; ")}` };
  }
  // Unused-variable guard against future silent canonicalization drift:
  // cgCanon stays imported so the digest convention stays one import away.
  void cgCanon;

  return { subject: [{ name: bundleName, digest: { sha256: bundleSha256hex } }], predicate };
}

export function buildHelmRunStatement(bundleFileText, bundleName) {
  const bundleSha256hex = createHash("sha256").update(bundleFileText).digest("hex");
  let bundle;
  try {
    bundle = JSON.parse(bundleFileText);
  } catch (err) {
    throw { exitCode: EXIT.EXPORT_FAILURE, message: `not a valid bundle.json — ${String(err?.message || err)}` };
  }
  const { subject, predicate } = buildHelmRunPredicate({ bundle, bundleSha256hex, bundleName });
  return buildStatement({
    subject,
    predicateType: HELM_RUN_PREDICATE_TYPE,
    predicate,
  });
}

function usage() {
  console.error(`usage: helmd export-intoto <bundle.json> [--out statement.json] [--json]

Export a Helm evidence bundle as an in-toto Statement v1 with the registered
predicate type ${HELM_RUN_PREDICATE_TYPE}, wrapped in the same
dual-signature DSSE envelope every Helm object already gets (Ed25519 MUST +
ML-DSA-44 SHOULD, hub/envelope.mjs), written to statement.json. Signed with
this install's own at-rest keys — no daemon required; helmd bilat-pubkey
prints those public keys for a counterparty.

Digest-level only: the predicate carries run id, digests, per-step
digests, and trust labels — never raw payload bytes (the upstream
redaction refusal list from hub/bundle.mjs is enforced here too).

Exit codes:
  0  statement written
  1  export failure (not an evidence bundle, secret-shaped field,
     self-inconsistent provenance, schema failure, key material
     unavailable) — nothing was written
  2  usage error (missing/malformed bundle path)`);
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes("-h") || rawArgs.includes("--help")) {
    usage();
    process.exit(0);
  }
  const jsonMode = rawArgs.includes("--json");
  let outPath;
  const positional = [];
  for (let i = 0; i < rawArgs.length; i++) {
    const a = rawArgs[i];
    if (a === "--out") { outPath = rawArgs[++i]; continue; }
    if (a.startsWith("--")) continue;
    positional.push(a);
  }
  const [bundlePath] = positional;
  if (!bundlePath) {
    usage();
    process.exit(EXIT.USAGE_ERROR);
  }

  let bundleFileText;
  try {
    bundleFileText = readFileSync(bundlePath, "utf8");
  } catch {
    console.error(`helmd export-intoto: cannot read bundle "${bundlePath}"`);
    process.exit(EXIT.USAGE_ERROR);
  }

  let statement;
  try {
    statement = buildHelmRunStatement(bundleFileText, basename(bundlePath));
  } catch (err) {
    if (err && err.exitCode === EXIT.EXPORT_FAILURE) {
      console.error(`helmd export-intoto: ${err.message}`);
      process.exit(EXIT.EXPORT_FAILURE);
    }
    throw err;
  }

  let keys;
  try {
    keys = loadOrCreateKeys();
  } catch (err) {
    console.error(`helmd export-intoto: key material unavailable — ${String(err?.message || err)}`);
    process.exit(EXIT.EXPORT_FAILURE);
  }

  const envelope = emitEnvelope(statement, keys);
  const finalOut = outPath ?? "statement.json";
  writeFileSync(finalOut, JSON.stringify(envelope, null, 2));

  if (jsonMode) {
    console.log(JSON.stringify({ ok: true, out: finalOut, predicateType: HELM_RUN_PREDICATE_TYPE, subject: statement.subject[0].name, algorithms: envelope.signatures.map((s) => s.alg) }));
  } else {
    console.log(`helmd export-intoto: wrote ${finalOut} (predicateType ${HELM_RUN_PREDICATE_TYPE}, subject ${statement.subject[0].name})`);
    console.log("  signed: EdDSA (Ed25519) + ML-DSA-44 — the same dual-sig envelope every Helm object gets");
  }
  process.exit(EXIT.OK);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main();
}
