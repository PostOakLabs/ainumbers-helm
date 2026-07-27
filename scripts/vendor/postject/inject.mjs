// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Integrity-checked wrapper around the vendored postject@1.0.0-alpha.6
// injector (HELM-POSTJECT-PIN-1). build-sea.mjs/sea-dry-run.mjs previously
// ran `npx --yes postject@1.0.0-alpha.6` — a VERSION pin, not an INTEGRITY
// pin: the bytes fetched at build time were whatever the npm registry served
// for that version at that moment, inside the exact pipeline whose
// provenance we attest. Vendoring the injector's bytes (MIT-licensed,
// self-contained — its only runtime dependency, `commander`, is used by
// postject's CLI wrapper, not by dist/api.js, so vendoring api.js alone
// avoids needing commander too) removes the build-time fetch entirely, and
// this module re-verifies the vendored bytes against MANIFEST.json's
// recorded sha256 on every call — a tampered or corrupted vendored file
// fails the build loudly instead of silently injecting different bytes.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = join(HERE, "MANIFEST.json");
const API_PATH = join(HERE, "api.cjs");

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function verifyVendoredBytes() {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
  const entry = (manifest.files || []).find((f) => f.path === "api.cjs");
  if (!entry || !entry.sha256) {
    throw new Error("postject inject.mjs: MANIFEST.json has no recorded sha256 for api.cjs — refusing to inject");
  }
  const actual = sha256(API_PATH);
  if (actual !== entry.sha256) {
    throw new Error(
      `postject inject.mjs: vendored api.cjs integrity FAILED — expected sha256 ${entry.sha256}, got ${actual}. ` +
        "The vendored injector does not match its recorded MANIFEST.json hash; refusing to inject into a SEA binary " +
        "with unverified bytes. If this is an intentional update, re-vendor via the documented process and update MANIFEST.json."
    );
  }
}

/**
 * Inject a resource into a SEA executable using the integrity-verified
 * vendored postject injector. Mirrors postject's CLI args 1:1
 * (filename, resourceName, resourcePath, { sentinelFuse, machoSegmentName, overwrite }).
 */
export async function injectSEA(filename, resourceName, resourcePath, options = {}) {
  verifyVendoredBytes();
  const require = createRequire(import.meta.url);
  const { inject } = require(API_PATH);
  const resourceData = readFileSync(resourcePath);
  await inject(filename, resourceName, resourceData, options);
}
