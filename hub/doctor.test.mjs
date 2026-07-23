import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-doctor-test-"));
process.env.HELM_HOME = TMP;

const { runDoctor } = await import("./doctor.mjs");

test("doctor: all checks pass on a fresh state dir", async () => {
  const report = await runDoctor();
  assert.equal(report.ok, true, JSON.stringify(report.checks));
  rmSync(TMP, { recursive: true, force: true });
});
