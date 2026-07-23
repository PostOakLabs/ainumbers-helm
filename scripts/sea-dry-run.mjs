#!/usr/bin/env node
// SEA build dry-run: generates the Node single-executable blob from hub/index.mjs
// but does NOT inject it into a runnable binary (that needs postject at
// packaging time, HELM-H8). Proves the entrypoint + sea-config stay buildable.
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { seaAssetMap } from "../hub/ui-manifest.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const entry = join(ROOT, "hub", "index.mjs");

if (!existsSync(entry)) {
  console.error(`sea-dry-run: missing entrypoint ${entry}`);
  process.exit(1);
}

const tmp = mkdtempSync(join(tmpdir(), "helm-sea-"));
try {
  const configPath = join(tmp, "sea-config.json");
  const blobPath = join(tmp, "helmd.blob");
  writeFileSync(
    configPath,
    JSON.stringify(
      { main: entry, output: blobPath, disableExperimentalSEAWarning: true, assets: seaAssetMap() },
      null,
      2
    )
  );
  execFileSync(process.execPath, ["--experimental-sea-config", configPath], { stdio: "inherit" });
  if (!existsSync(blobPath)) {
    console.error("sea-dry-run: blob was not produced");
    process.exit(1);
  }
  console.log("sea-dry-run: OK — blob generated");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
