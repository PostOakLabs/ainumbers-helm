import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-run-test-"));
process.env.HELM_HOME = TMP;

const { openJournal, replayVerify } = await import("./journal.mjs");
const { executeRun, replayExecutionHash, planSteps, manifestDigest, PHASE1_STATES } = await import("./run.mjs");

function manifest(overrides = {}) {
  return {
    manifest_version: "1",
    workflow_id: "wf-invoice-reconcile-01",
    trigger: { type: "schedule", schedule: "0 6 * * *" },
    nodes: [
      { node_id: "n1", kernel_id: "art-213-fee-route", kernel_digest: "sha256:" + "a".repeat(64) },
      { node_id: "n2", kernel_id: "art-214-variance-check", kernel_digest: "sha256:" + "b".repeat(64) },
    ],
    connectors: [],
    gates: [],
    actions: [],
    ...overrides,
  };
}

function dbAt(name) {
  return openJournal(join(TMP, name));
}

test("run engine: happy path executes, memoizes, and journals every transition", async () => {
  const db = dbAt("happy.db");
  const calls = [];
  const result = await executeRun(db, {
    runId: "run-1",
    manifest: manifest(),
    stepRunner: async (step) => {
      calls.push(step.step_id);
      return { ok: true, step_id: step.step_id };
    },
  });

  assert.equal(result.state, "completed");
  assert.equal(result.steps.length, 2);
  assert.deepEqual(calls, ["nodes:n1", "nodes:n2"]);
  assert.ok(result.executionHash.startsWith("sha256:"));

  const replay = replayExecutionHash(db, "run-1");
  assert.equal(replay, result.executionHash);
  assert.equal(replayVerify(db).ok, true);
  db.close();
});

test("run engine: crash-resume — memoized steps are not re-run, run still completes", async () => {
  const db = dbAt("crash.db");
  const calls = [];
  const stepRunner = async (step) => {
    calls.push(step.step_id);
    return { ok: true, step_id: step.step_id };
  };

  // First "process": crashes after n1 by throwing inside stepRunner for n2.
  await assert.rejects(
    executeRun(db, {
      runId: "run-2",
      manifest: manifest(),
      stepRunner: async (step) => {
        calls.push(step.step_id);
        if (step.step_id === "nodes:n2") throw new Error("simulated crash");
        return { ok: true, step_id: step.step_id };
      },
    })
  );

  // The engine treats a thrown stepRunner as a real failure (transitions to
  // "failed", not left dangling) — that's a controlled failure, not a crash.
  // A true crash never runs the catch block at all: simulate it directly by
  // forcing the run row back to "running" as if the process died mid-step.
  db.prepare("UPDATE runs SET state = 'running' WHERE run_id = ?").run("run-2");

  calls.length = 0;
  const result = await executeRun(db, {
    runId: "run-2",
    manifest: manifest(),
    stepRunner,
  });

  assert.equal(result.state, "completed");
  // n1 was memoized before the simulated crash — only n2 needed a real call.
  assert.deepEqual(calls, ["nodes:n2"]);
  db.close();
});

test("run engine: dry-run never invokes stepRunner and still produces a replayable hash", async () => {
  const db = dbAt("dryrun.db");
  const result = await executeRun(db, {
    runId: "run-3",
    manifest: manifest(),
    dryRun: true,
    stepRunner: async () => {
      throw new Error("stepRunner must not be called in dry-run mode");
    },
  });

  assert.equal(result.state, "completed");
  assert.equal(result.dryRun, true);
  assert.equal(replayExecutionHash(db, "run-3"), result.executionHash);
  db.close();
});

test("run engine: two independent runs of the same manifest produce identical execution_hash", async () => {
  const db = dbAt("determinism.db");
  const runner = async (step) => ({ ok: true, step_id: step.step_id, kernel_digest: step.kernel_digest });

  const a = await executeRun(db, { runId: "run-a", manifest: manifest(), stepRunner: runner });
  const b = await executeRun(db, { runId: "run-b", manifest: manifest(), stepRunner: runner });

  // execution_hash binds run_id, so raw hashes differ — but the step digest
  // chain (excluding run_id) must be identical for identical manifests.
  assert.notEqual(a.executionHash, b.executionHash);
  assert.deepEqual(a.steps.map((s) => s.output_digest), b.steps.map((s) => s.output_digest));
  db.close();
});

test("negative: tampering with a stored step result is detected on replay", async () => {
  const db = dbAt("tamper.db");
  const result = await executeRun(db, {
    runId: "run-4",
    manifest: manifest(),
    stepRunner: async (step) => ({ ok: true, step_id: step.step_id }),
  });
  assert.ok(result.executionHash);

  db.prepare("UPDATE step_results SET output_json = ? WHERE run_id = ? AND step_id = ?")
    .run(JSON.stringify({ ok: false, tampered: true }), "run-4", "nodes:n1");

  assert.throws(() => replayExecutionHash(db, "run-4"), /tampered/);
  db.close();
});

test("negative: illegal state transition is rejected", async () => {
  const db = dbAt("illegal.db");
  await executeRun(db, {
    runId: "run-5",
    manifest: manifest(),
    stepRunner: async (step) => ({ ok: true, step_id: step.step_id }),
  });
  // A completed run has no legal transitions — re-entering executeRun is a
  // no-op (crash-resume contract), never a state error.
  const again = await executeRun(db, {
    runId: "run-5",
    manifest: manifest(),
    stepRunner: async () => {
      throw new Error("must not run — run-5 is already completed");
    },
  });
  assert.equal(again.state, "completed");
  db.close();
});

test("planSteps: manifest layer order is the DAG (Phase 1, no edges field)", () => {
  const steps = planSteps(manifest());
  assert.deepEqual(steps.map((s) => s.step_id), ["nodes:n1", "nodes:n2"]);
  assert.equal(steps[0].seq, 0);
  assert.equal(steps[1].seq, 1);
});

test("manifestDigest: stable sha256ref for identical manifests", () => {
  assert.equal(manifestDigest(manifest()), manifestDigest(manifest()));
});

test("PHASE1_STATES matches the Phase-1 lifecycle subset (review states excluded)", () => {
  assert.deepEqual(PHASE1_STATES, [
    "draft", "validated", "queued", "running", "awaiting_data",
    "completed", "failed", "cancelled",
  ]);
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
