// Freshness gate for docs/openapi.json (HELM-P4-B2). Rides scripts/test.mjs
// (already CI-wired) so a route added to hub/server.mjs without regenerating
// docs/openapi.json fails the build — feedback-ssot-generator-freshness-gate.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildOpenApiDoc } from "./gen-openapi.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

test("docs/openapi.json matches hub/server.mjs's route table", () => {
  const rendered = JSON.stringify(buildOpenApiDoc(), null, 2) + "\n";
  const onDisk = readFileSync(join(ROOT, "docs", "openapi.json"), "utf8");
  assert.equal(onDisk, rendered, "docs/openapi.json is stale — run `node scripts/gen-openapi.mjs` and commit the diff");
});
