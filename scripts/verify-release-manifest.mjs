#!/usr/bin/env node
// Verifies a signed release manifest: DSSE dual-signature against the
// committed public release-signing key, then every subject artifact's
// sha256 against the files actually present in dist/. Used by CI (post-sign
// gate), doctor.mjs (post-install sanity), and documented for end users
// verifying a downloaded release by hand.
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyEnvelope } from "../hub/envelope.mjs";
import { loadReleasePublicKeys } from "../hub/release-keys.mjs";
import { cgCanon } from "../hub/vendored/ocg/kernels/_hash.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function verifyReleaseManifest(distDir, publicKeys = loadReleasePublicKeys()) {
  const manifestPath = join(distDir, "release-manifest.json");
  const dssePath = join(distDir, "release-manifest.dsse.json");
  if (!existsSync(manifestPath) || !existsSync(dssePath)) {
    return { ok: false, reason: "release-manifest.json or .dsse.json missing" };
  }

  const statement = JSON.parse(readFileSync(manifestPath, "utf8"));
  const envelope = JSON.parse(readFileSync(dssePath, "utf8"));

  const sig = verifyEnvelope(envelope, publicKeys);
  if (!sig.valid) {
    return { ok: false, reason: "signature invalid", sig: { ed25519: sig.ed25519, mldsa44: sig.mldsa44 } };
  }
  // release-manifest.json is a human-readable convenience copy of the signed
  // payload; compare canonically (key order is not semantically meaningful)
  // rather than trusting it — the signature over sig.statement is the SSOT.
  if (JSON.stringify(cgCanon(sig.statement.subject)) !== JSON.stringify(cgCanon(statement.subject))) {
    return { ok: false, reason: "envelope payload does not match release-manifest.json" };
  }

  const mismatches = [];
  for (const entry of sig.statement.subject) {
    const artifactPath = join(distDir, entry.name);
    if (!existsSync(artifactPath)) {
      mismatches.push({ name: entry.name, error: "missing on disk" });
      continue;
    }
    const actual = sha256(artifactPath);
    if (actual !== entry.digest.sha256) {
      mismatches.push({ name: entry.name, expected: entry.digest.sha256, actual });
    }
  }
  if (mismatches.length > 0) {
    return { ok: false, reason: "artifact digest mismatch", mismatches };
  }

  return { ok: true, version: statement.predicate.version, artifactCount: statement.subject.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const distDir = process.argv[2] ? join(process.cwd(), process.argv[2]) : join(ROOT, "dist");
  const result = verifyReleaseManifest(distDir);
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.ok ? 0 : 1);
}
