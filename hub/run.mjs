// Run engine (D4, HELM-H4): SQLite step-checkpoint executor over the H3
// journal. A workflow manifest's `nodes[]` has no edges field yet (§26.3) —
// Phase 1 treats manifest order as the DAG (a linear chain); a later WU that
// adds edges only needs to change planSteps(), not the executor around it.
//
// Every step result is memoized by (run_id, step_id, input_digest) so
// crash-resume and deterministic replay are the SAME code path: resuming a
// run just means the early steps' memo lookups hit instead of miss.
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "./vendored/ocg/kernels/_hash.mjs";
import { appendEntry } from "./journal.mjs";

// Phase-1 lifecycle subset (SPEC.md §26.5 defines the full enum; review
// states are Phase 2). Only these are reachable through this engine.
const PHASE1_STATES = [
  "draft", "validated", "queued", "running", "awaiting_data",
  "completed", "failed", "cancelled",
];

const ALLOWED_TRANSITIONS = {
  __start__: ["draft"],
  draft: ["validated", "cancelled"],
  validated: ["queued", "cancelled"],
  queued: ["running", "cancelled"],
  running: ["awaiting_data", "completed", "failed", "cancelled"],
  awaiting_data: ["running", "cancelled"],
  completed: [],
  failed: [],
  cancelled: [],
};

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

function sha256ref(hex) {
  return `sha256:${hex}`;
}

export function initRunTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS runs (
      run_id TEXT PRIMARY KEY,
      workflow_manifest_digest TEXT NOT NULL,
      manifest_json TEXT NOT NULL,
      dry_run INTEGER NOT NULL DEFAULT 0,
      state TEXT NOT NULL,
      execution_hash TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS step_results (
      run_id TEXT NOT NULL,
      step_id TEXT NOT NULL,
      input_digest TEXT NOT NULL,
      output_json TEXT NOT NULL,
      output_digest TEXT NOT NULL,
      completed_at TEXT NOT NULL,
      PRIMARY KEY (run_id, step_id, input_digest)
    );
  `);
}

export function manifestDigest(manifest) {
  return sha256ref(jcsDigestHex(manifest));
}

// Phase 1: manifest layer order IS the DAG (§26.3 has no edges field yet).
// Same convention as ui/lib/manifest-dag.mjs (buildDag): connectors -> nodes
// -> gates -> actions, `${layerKey}:${item_id}` as the stable id — trigger
// starts a run rather than being executed as a step, so it's excluded here.
// Within a layer, array order is the execution order (a hand-rolled
// executor has no reason to reach for real parallelism in Phase 1).
const STEP_LAYERS = [
  { key: "connectors", idField: "connector_id" },
  { key: "nodes", idField: "node_id" },
  { key: "gates", idField: "gate_id" },
  { key: "actions", idField: "action_id" },
];

export function planSteps(manifest) {
  const steps = [];
  let seq = 0;
  for (const { key, idField } of STEP_LAYERS) {
    for (const item of manifest[key] ?? []) {
      steps.push({
        step_id: `${key}:${item[idField]}`,
        kind: key,
        item,
        // nodes carry kernel_digest; other kinds fold their whole item into
        // the content digest below since they have no single pin field.
        contentDigest: item.kernel_digest ?? jcsDigestHex(item),
        seq: seq++,
      });
    }
  }
  return steps;
}

function stepInputDigest({ runId, step, priorOutputDigest, dryRun }) {
  return sha256ref(jcsDigestHex({
    run_id: runId,
    step_id: step.step_id,
    content_digest: step.contentDigest,
    prior_output_digest: priorOutputDigest,
    dry_run: !!dryRun,
  }));
}

// Recomputes output_digest from the stored payload on every read — a memo
// row whose output_json was altered after the fact (bit-rot or tamper) fails
// loudly here instead of silently feeding a wrong value into the chain.
function getMemoizedStep(db, { runId, stepId, inputDigest }) {
  const row = db
    .prepare("SELECT output_json, output_digest FROM step_results WHERE run_id = ? AND step_id = ? AND input_digest = ?")
    .get(runId, stepId, inputDigest);
  if (!row) return null;
  const output = JSON.parse(row.output_json);
  const recomputed = sha256ref(jcsDigestHex(output));
  if (recomputed !== row.output_digest) {
    throw new Error(`run engine: step_results tampered — run=${runId} step=${stepId} expected=${row.output_digest} found=${recomputed}`);
  }
  return { output, outputDigest: row.output_digest };
}

function saveStepResult(db, { runId, stepId, inputDigest, output }) {
  const outputDigest = sha256ref(jcsDigestHex(output));
  db.prepare(
    "INSERT OR REPLACE INTO step_results (run_id, step_id, input_digest, output_json, output_digest, completed_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(runId, stepId, inputDigest, JSON.stringify(output), outputDigest, new Date().toISOString());
  return outputDigest;
}

function nextJournalSeq(db) {
  const row = db.prepare("SELECT MAX(seq) AS m FROM journal").get();
  return (row.m ?? 0) + 1;
}

// entry Art.12 fields are populated here, not derived by journal.mjs (D6
// doctrine): triggering_input_digest = the manifest digest that caused this
// transition; humans_involved defaults empty for an unattended run engine.
function transitionState(db, { runId, workflowManifestDigest, fromState, toState, humansInvolved = [] }) {
  const allowedFrom = fromState === null ? "__start__" : fromState;
  if (!ALLOWED_TRANSITIONS[allowedFrom]?.includes(toState)) {
    throw new Error(`run engine: illegal transition ${fromState ?? "(start)"} -> ${toState} for run ${runId}`);
  }
  const now = new Date().toISOString();
  const journalSeq = nextJournalSeq(db);
  const entry = {
    state: toState,
    prev_state: fromState ?? "draft",
    journal_seq: journalSeq,
    run_id: runId,
    workflow_manifest_digest: workflowManifestDigest,
    period_start: now,
    period_end: now,
    reference_db_version: "helm-run-engine@1",
    triggering_input_digest: workflowManifestDigest,
    humans_involved: humansInvolved,
  };
  const { seq } = appendEntry(db, { streamId: `run:${runId}`, kind: "execution_state", runId, entry });
  if (seq !== journalSeq) {
    throw new Error(`run engine: journal_seq prediction drifted (predicted ${journalSeq}, assigned ${seq}) — single-writer invariant violated`);
  }
  db.prepare("UPDATE runs SET state = ? WHERE run_id = ?").run(toState, runId);
  return { seq, state: toState };
}

function currentState(db, runId) {
  return db.prepare("SELECT state FROM runs WHERE run_id = ?").get(runId)?.state ?? null;
}

// stepRunner(step, {priorOutputDigest, runId}) -> JSON-serializable output.
// Never invoked for a step whose (run_id, step_id, input_digest) is already
// memoized, and never invoked at all in dryRun mode — dry-run output is a
// synthetic {dry_run:true, step_id} placeholder, cheap enough to memoize the
// same way so a dry-run and a real run of the same manifest don't collide
// (dry_run is baked into the input digest).
//
// Idempotent + resumable: calling this again on a run left mid-flight by a
// crash (state still "running", some steps memoized) replays the memoized
// steps for free and only re-invokes stepRunner for what's left.
export async function executeRun(db, { runId, manifest, stepRunner, dryRun = false, humansInvolved = [] }) {
  initRunTables(db);
  const workflowManifestDigest = manifestDigest(manifest);
  const steps = planSteps(manifest);

  if (!db.prepare("SELECT 1 FROM runs WHERE run_id = ?").get(runId)) {
    db.prepare(
      "INSERT INTO runs (run_id, workflow_manifest_digest, manifest_json, dry_run, state, created_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(runId, workflowManifestDigest, JSON.stringify(manifest), dryRun ? 1 : 0, "draft", new Date().toISOString());
    transitionState(db, { runId, workflowManifestDigest, fromState: null, toState: "draft", humansInvolved });
    transitionState(db, { runId, workflowManifestDigest, fromState: "draft", toState: "validated", humansInvolved });
    transitionState(db, { runId, workflowManifestDigest, fromState: "validated", toState: "queued", humansInvolved });
  }

  let state = currentState(db, runId);
  if (state === "queued") {
    transitionState(db, { runId, workflowManifestDigest, fromState: "queued", toState: "running", humansInvolved });
    state = "running";
  }
  if (state !== "running") {
    // Already terminal (completed/failed/cancelled) — crash-resume no-op.
    return { runId, state, executionHash: db.prepare("SELECT execution_hash FROM runs WHERE run_id = ?").get(runId)?.execution_hash ?? null, steps: [] };
  }

  let priorOutputDigest = null;
  const stepDigests = [];
  try {
    for (const step of steps) {
      const inputDigest = stepInputDigest({ runId, step, priorOutputDigest, dryRun });
      let memo = getMemoizedStep(db, { runId, stepId: step.step_id, inputDigest });
      if (!memo) {
        const output = dryRun
          ? { dry_run: true, step_id: step.step_id, kind: step.kind }
          : await stepRunner(step, { priorOutputDigest, runId });
        const outputDigest = saveStepResult(db, { runId, stepId: step.step_id, inputDigest, output });
        memo = { output, outputDigest };
      }
      stepDigests.push({ step_id: step.step_id, input_digest: inputDigest, output_digest: memo.outputDigest });
      priorOutputDigest = memo.outputDigest;
    }
  } catch (err) {
    transitionState(db, { runId, workflowManifestDigest, fromState: "running", toState: "failed", humansInvolved });
    throw err;
  }

  const executionHash = sha256ref(jcsDigestHex({ run_id: runId, workflow_manifest_digest: workflowManifestDigest, steps: stepDigests }));
  db.prepare("UPDATE runs SET execution_hash = ? WHERE run_id = ?").run(executionHash, runId);
  transitionState(db, { runId, workflowManifestDigest, fromState: "running", toState: "completed", humansInvolved });

  return { runId, state: "completed", executionHash, steps: stepDigests, dryRun };
}

// Pure replay: recomputes execution_hash from persisted state only — no
// manifest re-fetch, no stepRunner call. This is the deterministic-replay
// gate: a run's recorded execution_hash MUST equal what this returns.
export function replayExecutionHash(db, runId) {
  initRunTables(db);
  const run = db.prepare("SELECT * FROM runs WHERE run_id = ?").get(runId);
  if (!run) throw new Error(`run engine: replay — unknown run_id ${runId}`);
  const manifest = JSON.parse(run.manifest_json);
  const steps = planSteps(manifest);

  let priorOutputDigest = null;
  const stepDigests = [];
  for (const step of steps) {
    const inputDigest = stepInputDigest({ runId, step, priorOutputDigest, dryRun: !!run.dry_run });
    const memo = getMemoizedStep(db, { runId, stepId: step.step_id, inputDigest });
    if (!memo) throw new Error(`run engine: replay — missing memoized result for run=${runId} step=${step.step_id}`);
    stepDigests.push({ step_id: step.step_id, input_digest: inputDigest, output_digest: memo.outputDigest });
    priorOutputDigest = memo.outputDigest;
  }
  return sha256ref(jcsDigestHex({ run_id: runId, workflow_manifest_digest: run.workflow_manifest_digest, steps: stepDigests }));
}

export { PHASE1_STATES };
