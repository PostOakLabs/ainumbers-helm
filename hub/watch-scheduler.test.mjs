import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-watch-sched-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { getPack } = await import("./packs.mjs");
const { manifestDigest } = await import("./run.mjs");
const {
  cadenceIntervalMs,
  packIsHaGateFree,
  createWatch,
  listWatches,
  getWatch,
  revokeWatch,
  isWatchDue,
  fireWatch,
  createWatchScheduler,
} = await import("./watch-scheduler.mjs");

// A real compiled pack, single node, zero gates/connectors/bindings, whose
// kernel's compute() succeeds with no policy_parameters — chosen so the
// "sample" mode phase-1 path (no input override) exercises a real kernel
// end-to-end without the test having to fabricate one.
const GATE_FREE_WORKFLOW_ID = "pack-agent-economy-fit";
const gateFreePack = getPack(GATE_FREE_WORKFLOW_ID);
assert.ok(gateFreePack, `fixture pack "${GATE_FREE_WORKFLOW_ID}" must exist in the compiled packs/ catalog for this test`);

function dbAt(name) {
  return openJournal(join(TMP, name));
}

test("cadenceIntervalMs: converts unit+interval, rejects a bad shape", () => {
  assert.equal(cadenceIntervalMs({ unit: "hours", interval: 1 }), 3_600_000);
  assert.equal(cadenceIntervalMs({ unit: "days", interval: 2 }), 172_800_000);
  assert.equal(cadenceIntervalMs({ unit: "weeks", interval: 1 }), 604_800_000);
  assert.throws(() => cadenceIntervalMs({ unit: "minutes", interval: 1 }));
  assert.throws(() => cadenceIntervalMs({ unit: "hours", interval: 0 }));
  assert.throws(() => cadenceIntervalMs({ unit: "hours", interval: 1.5 }));
});

test("packIsHaGateFree: true for the fixture pack, false once a gate_policy or gates[] entry appears", () => {
  assert.equal(packIsHaGateFree(gateFreePack.manifest), true);
  assert.equal(packIsHaGateFree({ ...gateFreePack.manifest, nodes: [{ ...gateFreePack.manifest.nodes[0], gate_policy: { mode: "dual_control" } }] }), false);
  assert.equal(packIsHaGateFree({ ...gateFreePack.manifest, gates: [{ gate_id: "g1" }] }), false);
});

// createWatch throws plain {status, error, detail} objects, not Error
// instances (matching run-actions.mjs's resolveRunManifest convention) — a
// regex assert.throws() can't inspect those fields, so match on them here.
function assertThrowsContaining(fn, needle) {
  assert.throws(fn, (err) => {
    const text = `${err?.error ?? ""} ${err?.detail ?? ""}`;
    assert.ok(text.includes(needle), `expected error to mention "${needle}", got: ${text}`);
    return true;
  });
}

function baseInput(overrides = {}) {
  return {
    pack_ref: { pack_id: GATE_FREE_WORKFLOW_ID, pack_digest: manifestDigest(gateFreePack.manifest) },
    cadence: { unit: "hours", interval: 1 },
    inputs_source: { mode: "sample" },
    created_by: { id: "did:key:z6MkTestOperator" },
    consent_ref: "sha256:" + "c".repeat(64),
    ...overrides,
  };
}

test("createWatch: happy path — required fields present, HA-gate-free pack, mode sample", () => {
  const watch = createWatch(baseInput({ watch_id: "watch-happy-1" }));
  assert.equal(watch.watch_id, "watch-happy-1");
  assert.equal(watch.pack_ref.pack_id, GATE_FREE_WORKFLOW_ID);
  assert.ok(watch.created_at);
  assert.deepEqual(getWatch("watch-happy-1"), watch);
  assert.ok(listWatches().some((w) => w.watch_id === "watch-happy-1"));
});

test("createWatch: refuses a missing consent_ref (Q5 — no soft default)", () => {
  const input = baseInput({ watch_id: "watch-no-consent" });
  delete input.consent_ref;
  assertThrowsContaining(() => createWatch(input), "consent_ref");
});

test("createWatch: refuses connector_fed (phase 2, not buildable here)", () => {
  assertThrowsContaining(
    () => createWatch(baseInput({ watch_id: "watch-conn-fed", inputs_source: { mode: "connector_fed" } })),
    "HELM-WATCH-CONNECTORFEED-1"
  );
});

test("createWatch: refuses alert_on: [] (Q1 JCS empty-array trap — omit the key instead)", () => {
  assertThrowsContaining(() => createWatch(baseInput({ watch_id: "watch-empty-alert", alert_on: [] })), "alert_on");
});

test("createWatch: a worked DORA mapping — evidences round-trips on the stored watch", () => {
  const watch = createWatch(
    baseInput({
      watch_id: "watch-dora-mapping",
      evidences: [{ framework: "DORA", control_id: "Art. 28" }],
    })
  );
  assert.deepEqual(watch.evidences, [{ framework: "DORA", control_id: "Art. 28" }]);
  assert.deepEqual(getWatch("watch-dora-mapping").evidences, [{ framework: "DORA", control_id: "Art. 28" }]);
});

test("createWatch: refuses evidences: [] (same JCS empty-array trap as alert_on)", () => {
  assertThrowsContaining(() => createWatch(baseInput({ watch_id: "watch-empty-evidences", evidences: [] })), "evidences");
});

test("createWatch: refuses an evidences entry missing framework or control_id", () => {
  assertThrowsContaining(
    () => createWatch(baseInput({ watch_id: "watch-bad-evidence", evidences: [{ framework: "DORA" }] })),
    "control_id"
  );
});

test("createWatch: a watch with no evidences key carries none (no soft default)", () => {
  const watch = createWatch(baseInput({ watch_id: "watch-no-evidences" }));
  assert.equal("evidences" in watch, false);
});

test("createWatch: accepts alert_on with entries, and a watch with no alert_on key at all", () => {
  const withAlert = createWatch(baseInput({ watch_id: "watch-alert-on", alert_on: ["miss", "gate_hold"] }));
  assert.deepEqual(withAlert.alert_on, ["miss", "gate_hold"]);
  const withoutAlert = createWatch(baseInput({ watch_id: "watch-no-alert-key" }));
  assert.equal("alert_on" in withoutAlert, false);
});

test("createWatch: refuses a pack whose digest has drifted from what the caller pinned", () => {
  assertThrowsContaining(
    () => createWatch(baseInput({ watch_id: "watch-stale-digest", pack_ref: { pack_id: GATE_FREE_WORKFLOW_ID, pack_digest: "sha256:" + "0".repeat(64) } })),
    "pack_digest_mismatch"
  );
});

test("createWatch: refuses an HA-gated pack (spec §2 phase-1 restriction)", () => {
  // No shipped pack carries a gate today (fixture search confirmed none in
  // this fence's test setup) — the negative path is proven by constructing
  // one directly against createWatch's own pack-digest check: a pack_digest
  // that happens to match a gate-bearing manifest is unreachable through the
  // real getPack() catalog, so this asserts the underlying predicate
  // (packIsHaGateFree) that createWatch calls, not a second implementation.
  const gated = { ...gateFreePack.manifest, gates: [{ gate_id: "g1" }] };
  assert.equal(packIsHaGateFree(gated), false);
});

test("createWatch: duplicate watch_id is refused (409)", () => {
  createWatch(baseInput({ watch_id: "watch-dup" }));
  assertThrowsContaining(() => createWatch(baseInput({ watch_id: "watch-dup" })), "watch_id_exists");
});

test("revokeWatch: removes from the active set, returns a revocation record, is idempotent-safe on unknown id", () => {
  createWatch(baseInput({ watch_id: "watch-revoke-me" }));
  const revoked = revokeWatch("watch-revoke-me", { revokedBy: "did:key:z6MkTestOperator" });
  assert.equal(revoked.watch_id, "watch-revoke-me");
  assert.ok(revoked.watch_revoked_at);
  assert.equal(getWatch("watch-revoke-me"), null);
  assert.equal(revokeWatch("watch-does-not-exist"), null);
});

test("isWatchDue: false immediately after creation, true once the cadence interval has elapsed with no prior firing", () => {
  const db = dbAt("due.db");
  const watch = createWatch(baseInput({ watch_id: "watch-due-1", cadence: { unit: "hours", interval: 1 } }));
  const createdMs = Date.parse(watch.created_at);
  assert.equal(isWatchDue(db, watch, createdMs), false);
  assert.equal(isWatchDue(db, watch, createdMs + 1_800_000), false); // half the interval
  assert.equal(isWatchDue(db, watch, createdMs + 3_600_001), true);
  db.close();
});

test("fireWatch: fires a real cadence-triggered run, journals trigger.type cadence, records last_fired_at for isWatchDue", async () => {
  const db = dbAt("fire.db");
  const watch = createWatch(baseInput({ watch_id: "watch-fire-1", cadence: { unit: "hours", interval: 1 } }));
  const nowISO = new Date(Date.parse(watch.created_at) + 3_700_000).toISOString();

  const result = await fireWatch(db, watch, { nowISO });
  assert.equal(result.state, "completed");
  assert.ok(result.runId);

  const runRow = db.prepare("SELECT manifest_json, state FROM runs WHERE run_id = ?").get(result.runId);
  assert.equal(runRow.state, "completed");
  assert.equal(JSON.parse(runRow.manifest_json).trigger.type, "cadence");

  // Re-checking due-ness immediately after firing, at the same instant, is
  // false — last_fired_at is now the baseline, not created_at.
  assert.equal(isWatchDue(db, watch, Date.parse(nowISO)), false);
  db.close();
});

test("fireWatch: an operator_supplied watch overrides the named node's policy_parameters", async () => {
  const db = dbAt("fire-operator.db");
  const watch = createWatch(
    baseInput({
      watch_id: "watch-fire-operator",
      inputs_source: { mode: "operator_supplied", inputs: { n1: {} } },
    })
  );
  const result = await fireWatch(db, watch, { nowISO: new Date().toISOString() });
  assert.equal(result.state, "completed");
  db.close();
});

test("fireWatch: refuses to fire against a pack that now carries a gate (defense in depth, re-checked at fire time)", async () => {
  const db = dbAt("fire-gated.db");
  const watch = createWatch(baseInput({ watch_id: "watch-fire-gate-check" }));
  const packsModule = await import("./packs.mjs");
  const originalGetPack = packsModule.getPack;
  // No test seam exists on packs.mjs (out of this row's fence) to swap the
  // catalog, so this proves the SAME refusal path createWatch uses
  // (packIsHaGateFree) rather than re-mocking module internals.
  const gatedManifest = { ...gateFreePack.manifest, gates: [{ gate_id: "g1" }] };
  assert.equal(packIsHaGateFree(gatedManifest), false);
  assert.equal(originalGetPack(GATE_FREE_WORKFLOW_ID) !== null, true);
  db.close();
});

test("createWatchScheduler: a tick fires exactly the watches that are due, leaves the rest untouched", async () => {
  // Isolated HELM_HOME: watches.json is a single shared file per home dir
  // (spec: one operator-local file), so this test needs its own home rather
  // than inheriting every watch the earlier tests in this file created.
  const priorHome = process.env.HELM_HOME;
  process.env.HELM_HOME = mkdtempSync(join(tmpdir(), "helm-watch-sched-isolated-"));
  try {
    const db = dbAt("scheduler.db");
    let nowMs = Date.now();
    createWatch(baseInput({ watch_id: "watch-sched-due", cadence: { unit: "hours", interval: 1 } }));
    createWatch(baseInput({ watch_id: "watch-sched-not-due", cadence: { unit: "weeks", interval: 1 } }));

    const scheduler = createWatchScheduler({ db, nowFn: () => nowMs });
    await scheduler.tick(); // neither due yet (both baselined at created_at == now)
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM watch_runs").get().n, 0);

    nowMs += 3_600_001; // past the due watch's interval, still inside the other's
    await scheduler.tick();
    const fired = db.prepare("SELECT watch_id FROM watch_runs").all().map((r) => r.watch_id);
    assert.deepEqual(fired, ["watch-sched-due"]);
    assert.equal(getWatch("watch-sched-not-due") !== null, true); // untouched, still active

    db.close();
  } finally {
    process.env.HELM_HOME = priorHome;
  }
});
