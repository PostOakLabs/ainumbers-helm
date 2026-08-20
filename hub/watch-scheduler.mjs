// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-WATCH-SCHED-1 (HELM-WATCH-BUILD-SPEC.md §1 Q1/Q2/Q4/Q5, §2, §4 row 1).
// Operator-local cadence loop: fires a compiled pack unattended on a fixed
// interval and journals the run under `trigger.type: "cadence"` (already an
// open string field on workflow-manifest.schema.json's `trigger` member — no
// schema edit). This module owns the watch config (`watches.json`, gitignored
// like every other runtime state under state-dir.mjs) and the loop that reads
// it; the freshness receipt computed OVER the resulting journal entries is a
// separate row (HELM-WATCH-RECEIPT-1), not built here.
//
// Phase 1 only (§2): `inputs_source.mode` is "sample" or "operator_supplied";
// "connector_fed" is refused at creation (HELM-WATCH-CONNECTORFEED-1, not
// staged). Cadence is a fixed interval, never a wall-clock cron expression
// (Q1) — SO #0's line: the receipt states what happened, this config states
// a spacing, neither promises a future run.
//
// HELM-WATCH-HAGATE-1: the "HA-gate-free packs only" restriction this row
// originally shipped is REMOVED — `HELM-MAKERCHECKER-BUILD-1` (board/done/)
// shipped MC-1 (distinct maker/checker identities enforced) and MC-2
// (attester_kind + distinct-human threshold), closing the one-keypair hole
// the restriction existed to guard against. A watch may now be created over
// any pack, gated or not (`packIsHaGateFree` stays exported as a pure
// predicate — informational only, no longer enforced at createWatch/fireWatch).
// A cadence-triggered run reaching a `gate_policy` step HOLDs exactly as an
// on-demand run would (Q5) — `fireWatch` already threads `haGateCheckFor(db)`
// into `executeRun` below; nothing about that plumbing changes here.
//
// 2026 enhancement (binding, staged): a watch definition carries an optional
// `evidences[]` field, each entry `{framework, control_id}` (CCM vocabulary —
// generic across control frameworks; DORA is the worked example below, not a
// hardcoded case), naming which control-framework article/id the watch's
// output evidences. The gap between a watch's intended cadence and what a
// receipt actually observed is named the DRIFT WINDOW — the term this row
// introduces into schema and copy, computed by HELM-WATCH-RECEIPT-1's
// `cadence_conformance` (spec §1 Q2: `expected_by`/`ran_at`) over the journal
// entries this scheduler produces. A worked example: a watch over a pack that
// checks ICT third-party risk register freshness might carry
// `evidences: [{framework: "DORA", control_id: "Art. 28"}]`, so an examiner
// reading its eventual receipt reads "this receipt evidences DORA Art. 28
// control freshness, drift window: <expected_by> to <ran_at>" directly.
import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { getPack } from "./packs.mjs";
import { executeRun, manifestDigest } from "./run.mjs";
import { createKernelStepRunner, validateKernelInputs } from "./kernel-runner.mjs";
import { publishRunEvent } from "./event-bus.mjs";
import { haGateCheckFor } from "./ha-gate.mjs";
import { log } from "./log.mjs";

const CADENCE_UNITS_MS = { hours: 3_600_000, days: 86_400_000, weeks: 604_800_000 };
const PHASE1_INPUT_MODES = new Set(["sample", "operator_supplied"]);
export const DEFAULT_WATCH_POLL_MS = 60_000;

export function cadenceIntervalMs(cadence) {
  const unitMs = CADENCE_UNITS_MS[cadence?.unit];
  if (!unitMs || !Number.isInteger(cadence?.interval) || cadence.interval < 1) {
    throw new Error(`watch-scheduler: invalid cadence — unit must be one of hours|days|weeks and interval an integer >= 1`);
  }
  return unitMs * cadence.interval;
}

// Pure predicate, kept for callers/tests that want to know whether a pack
// carries a gate_policy-bearing step or a non-empty gates[] (an approval
// checkpoint IS a gate by definition). HELM-WATCH-HAGATE-1 removed this
// function's use as a creation/firing restriction — see the module header.
export function packIsHaGateFree(manifest) {
  const hasGatePolicy = (arr) => (arr ?? []).some((item) => item?.gate_policy !== undefined);
  return !hasGatePolicy(manifest.nodes) && !hasGatePolicy(manifest.actions) && (manifest.gates ?? []).length === 0;
}

function loadWatchesFile(path) {
  if (!existsSync(path)) return [];
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    throw new Error(`watch-scheduler: watches.json is corrupt — ${err.message}`);
  }
}

function saveWatchesFile(path, watches) {
  writeFileSync(path, JSON.stringify(watches, null, 2), { mode: 0o600 });
}

// watches.json path is resolvable per-call (not cached at module load) so
// tests can point HELM_HOME at a fresh dir per case, matching state-dir.mjs's
// own per-call statePath() convention.
function watchesPath() {
  return statePath("watches.json");
}

export function listWatches() {
  return loadWatchesFile(watchesPath());
}

export function getWatch(watchId) {
  return listWatches().find((w) => w.watch_id === watchId) ?? null;
}

// Q1 shape validation — hand-rolled, not a JSON-Schema file: this is helmd's
// own operator-local config (spec §1 Q1), not an OCG artifact, so it carries
// no vendored $def. Every required field per the spec's shape block is
// checked; `alert_on`, when present, must be non-empty (the JCS empty-array
// trap Q1 names — an operator who wants zero alerting omits the key rather
// than sending `[]`, so a present empty array is refused as a caller error
// rather than silently accepted as "alerting configured to nothing").
function validateWatchInput(input) {
  const errors = [];
  if (typeof input?.pack_ref?.pack_id !== "string" || !input.pack_ref.pack_id) errors.push("pack_ref.pack_id is required");
  if (typeof input?.pack_ref?.pack_digest !== "string" || !input.pack_ref.pack_digest.startsWith("sha256:")) {
    errors.push("pack_ref.pack_digest is required and must be a sha256: ref");
  }
  try {
    cadenceIntervalMs(input?.cadence);
  } catch (err) {
    errors.push(err.message);
  }
  const mode = input?.inputs_source?.mode;
  if (!PHASE1_INPUT_MODES.has(mode)) {
    errors.push(
      mode === "connector_fed"
        ? "inputs_source.mode \"connector_fed\" is phase 2 (HELM-WATCH-CONNECTORFEED-1) — not buildable here (spec §2/§4 row 6)"
        : `inputs_source.mode must be one of ${[...PHASE1_INPUT_MODES].join("|")}`
    );
  }
  if (input?.alert_on !== undefined) {
    if (!Array.isArray(input.alert_on) || input.alert_on.length === 0) {
      errors.push("alert_on, when present, must be a non-empty array — omit the key entirely for a watch with no alerting (Q1 empty-array/JCS trap)");
    } else {
      const allowed = new Set(["miss", "result_change", "gate_hold"]);
      for (const a of input.alert_on) if (!allowed.has(a)) errors.push(`alert_on entry "${a}" is not one of miss|result_change|gate_hold`);
    }
  }
  // 2026 enhancement (binding, staged): `evidences[]` maps a watch's output to
  // the control-framework id it evidences — CCM vocabulary (`framework` +
  // `control_id`), generic across frameworks, DORA is the worked example, not
  // a hardcoded case. Optional and, when present, non-empty for the same
  // Q1 JCS-empty-array reason `alert_on` already enforces above: there is no
  // "evidences configured to nothing" state distinct from omitting the key.
  if (input?.evidences !== undefined) {
    if (!Array.isArray(input.evidences) || input.evidences.length === 0) {
      errors.push("evidences, when present, must be a non-empty array — omit the key entirely for a watch that evidences no named control");
    } else {
      input.evidences.forEach((e, i) => {
        if (typeof e?.framework !== "string" || !e.framework) errors.push(`evidences[${i}].framework is required (e.g. "DORA", "CCM")`);
        if (typeof e?.control_id !== "string" || !e.control_id) errors.push(`evidences[${i}].control_id is required (e.g. "Art. 17(3)")`);
      });
    }
  }
  if (typeof input?.created_by?.id !== "string" || !input.created_by.id) errors.push("created_by.id is required (did:key or LEI)");
  // Q5: consent-gated at creation, never inferred, never soft-defaulted. This
  // row does not mint or verify the signature behind consent_ref (that is
  // ha-store.mjs / the browser-held-key signing path §1 Q5 names) — it only
  // enforces that a caller who skipped it cannot create a watch at all.
  if (typeof input?.consent_ref !== "string" || !input.consent_ref) errors.push("consent_ref is required (Q5: consent-gated at creation, no soft default)");
  return errors;
}

// POST /watches handler core. Throws {status, error, detail} shaped errors,
// same convention as run-actions.mjs's resolveRunManifest, for the route to
// translate into an HTTP response.
export function createWatch(input) {
  const errors = validateWatchInput(input);
  if (errors.length) throw { status: 422, error: "invalid_watch", detail: errors.join("; ") };

  const pack = getPack(input.pack_ref.pack_id);
  if (!pack) throw { status: 404, error: "workflow_not_found" };
  const actualDigest = manifestDigest(pack.manifest);
  if (actualDigest !== input.pack_ref.pack_digest) {
    throw { status: 409, error: "pack_digest_mismatch", detail: `pack "${input.pack_ref.pack_id}" is now ${actualDigest}, watch requested ${input.pack_ref.pack_digest}` };
  }
  if (input.inputs_source.mode === "operator_supplied") {
    if (typeof input.inputs_source.inputs !== "object" || input.inputs_source.inputs === null || Array.isArray(input.inputs_source.inputs)) {
      throw { status: 422, error: "invalid_watch", detail: "inputs_source.mode \"operator_supplied\" requires inputs_source.inputs, an object keyed by node_id" };
    }
    for (const [nodeId, params] of Object.entries(input.inputs_source.inputs)) {
      const node = (pack.manifest.nodes ?? []).find((n) => n.node_id === nodeId);
      if (!node) throw { status: 422, error: "invalid_watch", detail: `inputs_source.inputs names node_id "${nodeId}", absent from pack "${input.pack_ref.pack_id}"` };
      const check = validateKernelInputs(node.kernel_id, params);
      if (!check.ok) throw { status: 422, error: "invalid_watch", detail: `inputs_source.inputs node "${nodeId}": ${check.error}` };
    }
  }

  const watch = {
    watch_id: input.watch_id || randomUUID(),
    pack_ref: { pack_id: input.pack_ref.pack_id, pack_digest: input.pack_ref.pack_digest },
    cadence: { unit: input.cadence.unit, interval: input.cadence.interval },
    inputs_source: input.inputs_source.mode === "operator_supplied"
      ? { mode: "operator_supplied", inputs: input.inputs_source.inputs }
      : { mode: "sample" },
    ...(input.alert_on !== undefined ? { alert_on: input.alert_on } : {}),
    ...(input.evidences !== undefined ? { evidences: input.evidences.map((e) => ({ framework: e.framework, control_id: e.control_id })) } : {}),
    created_at: new Date().toISOString(),
    created_by: { id: input.created_by.id },
    consent_ref: input.consent_ref,
  };

  const watches = listWatches();
  if (watches.some((w) => w.watch_id === watch.watch_id)) {
    throw { status: 409, error: "watch_id_exists" };
  }
  watches.push(watch);
  saveWatchesFile(watchesPath(), watches);
  return watch;
}

// Q5 revocation: additive evidence, never a delete of history — the watch is
// removed from the active scheduler set (this file) but every journal entry
// and consent record it already produced stays intact untouched by this
// function (they live in the journal DB, not watches.json).
export function revokeWatch(watchId, { revokedBy, nowISO = new Date().toISOString() } = {}) {
  const watches = listWatches();
  const idx = watches.findIndex((w) => w.watch_id === watchId);
  if (idx === -1) return null;
  const [removed] = watches.splice(idx, 1);
  saveWatchesFile(watchesPath(), watches);
  return { ...removed, watch_revoked_at: nowISO, revoked_by: revokedBy ?? null };
}

// --- cadence loop -----------------------------------------------------------

function initWatchRunsTable(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS watch_runs (
      watch_id TEXT PRIMARY KEY,
      last_fired_at TEXT NOT NULL,
      last_run_id TEXT NOT NULL,
      expected_by TEXT
    );
  `);
  // Migration for a watch_runs table created before HELM-WATCH-RECEIPT-1
  // (expected_by is new) — `ALTER TABLE ADD COLUMN` is idempotent-by-catch
  // here since node:sqlite's DatabaseSync has no
  // "column already exists"-safe IF NOT EXISTS variant for ADD COLUMN.
  try {
    db.exec("ALTER TABLE watch_runs ADD COLUMN expected_by TEXT");
  } catch {
    // column already present — expected on every call after the first.
  }
}

function lastFiredAt(db, watchId) {
  const row = db.prepare("SELECT last_fired_at FROM watch_runs WHERE watch_id = ?").get(watchId);
  return row ? row.last_fired_at : null;
}

// Exported for HELM-WATCH-RECEIPT-1: the same baseline isWatchDue computes
// internally (last cadence-triggered firing, or created_at before the first
// one), read-only, so the receipt row's freshness computation never
// re-derives this rule a second way.
export function watchBaseline(db, watchId, watch) {
  initWatchRunsTable(db);
  return lastFiredAt(db, watchId) ?? watch.created_at;
}

// The full watch_runs row (last_fired_at, last_run_id, expected_by) for a
// watch, or null if it has never fired. HELM-WATCH-RECEIPT-1 reads this
// directly rather than re-querying the table under a third name.
export function lastWatchRun(db, watchId) {
  initWatchRunsTable(db);
  const row = db.prepare("SELECT last_fired_at, last_run_id, expected_by FROM watch_runs WHERE watch_id = ?").get(watchId);
  return row ? { lastFiredAt: row.last_fired_at, lastRunId: row.last_run_id, expectedBy: row.expected_by } : null;
}

function recordFired(db, watchId, { runId, nowISO, expectedBy }) {
  db.prepare(
    "INSERT INTO watch_runs (watch_id, last_fired_at, last_run_id, expected_by) VALUES (?, ?, ?, ?) " +
      "ON CONFLICT(watch_id) DO UPDATE SET last_fired_at = excluded.last_fired_at, last_run_id = excluded.last_run_id, expected_by = excluded.expected_by"
  ).run(watchId, nowISO, runId, expectedBy);
}

// A watch is due when now >= baseline + one cadence interval, where baseline
// is its last cadence-triggered firing, or created_at before it has ever
// fired. Firing exactly at creation would journal a run before the operator
// has had a chance to look at what they just configured — one full interval
// grace period first is a deliberate, documented choice, not an oversight.
export function isWatchDue(db, watch, nowMs) {
  const baseline = watchBaseline(db, watch.watch_id, watch);
  return nowMs >= Date.parse(baseline) + cadenceIntervalMs(watch.cadence);
}

// Fires exactly one cadence-triggered run for `watch`. Mirrors
// run-actions.mjs's startWorkflowRun but deliberately narrower: `trigger`
// gains `type: "cadence"` (Q2 — the new trigger, no schema edit, `trigger`
// is already an open-string-field object), inputs come from the watch's own
// `inputs_source` rather than a caller argument, and callerOrigin is never
// "ui" — an unattended cadence firing must never gain connector/action
// dispatch capability an on-demand UI run has (HELM-BIND-WIRE-1's
// fail-closed discipline, reused here for a different caller). Awaited by
// the poll loop below (never fire-and-forget) so a scheduler tick's own
// caller can see failures rather than them evaporating into an
// unhandled-rejection.
export async function fireWatch(db, watch, { nowISO = new Date().toISOString() } = {}) {
  const pack = getPack(watch.pack_ref.pack_id);
  if (!pack) throw new Error(`watch-scheduler: fire — pack "${watch.pack_ref.pack_id}" no longer resolves for watch ${watch.watch_id}`);

  const manifest = { ...pack.manifest, trigger: { ...pack.manifest.trigger, type: "cadence" } };
  const clone = JSON.parse(JSON.stringify(manifest));
  const suppliedNodeIds = new Set();
  if (watch.inputs_source.mode === "operator_supplied") {
    clone.nodes = (clone.nodes ?? []).map((node) => {
      if (!Object.prototype.hasOwnProperty.call(watch.inputs_source.inputs, node.node_id)) return node;
      suppliedNodeIds.add(node.node_id);
      return { ...node, policy_parameters: watch.inputs_source.inputs[node.node_id] };
    });
  }

  // Captured BEFORE recordFired below advances the baseline — this is the
  // window this firing is satisfying (Q2's expected_by), not the window the
  // NEXT firing will be due in. HELM-WATCH-RECEIPT-1 reads it back verbatim
  // from watch_runs rather than recomputing it after the fact, since after
  // the fact the baseline has already moved to this run's own timestamp.
  const expectedBy = new Date(Date.parse(watchBaseline(db, watch.watch_id, watch)) + cadenceIntervalMs(watch.cadence)).toISOString();

  const runId = randomUUID();
  const kernelStepRunner = createKernelStepRunner();
  const stepRunner = async (step, ctx) => {
    const output = await kernelStepRunner(step, ctx);
    publishRunEvent(runId, { run_id: runId, state: "running", step_id: step.step_id });
    return output;
  };
  stepRunner.canDispatch = kernelStepRunner.canDispatch;

  const gateCheck = haGateCheckFor(db);
  const result = await executeRun(db, { runId, manifest: clone, dryRun: false, stepRunner, gateCheck });
  publishRunEvent(runId, { run_id: runId, state: result.state, execution_hash: result.executionHash, held: result.held ?? null });
  recordFired(db, watch.watch_id, { runId, nowISO, expectedBy });
  return { runId, state: result.state };
}

// Poll-based loop (never a wall-clock cron — Q1), checked once per
// `pollMs`. Watches are independent: one watch's fire failure (a pack that
// stopped resolving, a gate that appeared) is logged and never stops the
// tick from checking the rest, and never crashes the daemon (HELM-FRESHDB
// -CRASH-1's own belt-and-braces discipline, applied to this loop).
export function createWatchScheduler({ db, pollMs = DEFAULT_WATCH_POLL_MS, nowFn = () => Date.now(), setIntervalFn = setInterval, clearIntervalFn = clearInterval }) {
  initWatchRunsTable(db);
  let timer = null;

  async function tick() {
    const nowMs = nowFn();
    const nowISO = new Date(nowMs).toISOString();
    for (const watch of listWatches()) {
      let due;
      try {
        due = isWatchDue(db, watch, nowMs);
      } catch (err) {
        log.error("watch-scheduler: due-check failed", { watchId: watch.watch_id, error: String(err?.message || err) });
        continue;
      }
      if (!due) continue;
      try {
        const result = await fireWatch(db, watch, { nowISO });
        log.info("watch-scheduler: fired", { watchId: watch.watch_id, runId: result.runId, state: result.state });
      } catch (err) {
        log.error("watch-scheduler: fire failed", { watchId: watch.watch_id, error: String(err?.message || err) });
      }
    }
  }

  function start() {
    if (timer) return;
    timer = setIntervalFn(tick, pollMs);
    if (typeof timer.unref === "function") timer.unref();
  }

  function stop() {
    if (timer) clearIntervalFn(timer);
    timer = null;
  }

  return { start, stop, tick };
}
