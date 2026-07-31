// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-BIND-1: `connector_inputs[]` topology in the run engine (SPEC-S26
// §26.3.1, HELM-DATA-BINDING-BUILD-SPEC.md §2). Topology only — no value is
// resolved or threaded (§2.5).
//
// HELM-BIND-2 (§3, same file): value resolution and threading into
// stepInputDigest / policy_parameters. See the tests below the HELM-BIND-1
// block.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-bind-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { executeRun, planSteps, manifestDigest, validateManifestBindings, orderStepsByEdges } =
  await import("./run.mjs");

// Base manifest declares NO binding: per §0.3 both members must be genuinely
// ABSENT, never `[]`.
function manifest(overrides = {}) {
  return {
    manifest_version: "1",
    workflow_id: "wf-bind-01",
    trigger: { type: "schedule", schedule: "0 6 * * *" },
    connectors: [
      { connector_id: "c1", contract_digest: "sha256:" + "c".repeat(64) },
      { connector_id: "c2", contract_digest: "sha256:" + "d".repeat(64) },
    ],
    nodes: [
      { node_id: "n1", kernel_id: "art-213-fee-route", kernel_digest: "sha256:" + "a".repeat(64) },
      { node_id: "n2", kernel_id: "art-214-variance-check", kernel_digest: "sha256:" + "b".repeat(64) },
    ],
    gates: [],
    actions: [],
    ...overrides,
  };
}

function dbAt(name) {
  return openJournal(join(TMP, name));
}

function binding(o = {}) {
  return { step_id: "b1", connector_id: "c1", feeds_node_id: "n1", feeds_param: "amount", ...o };
}

test("planSteps: absent connector_inputs falls back to STEP_LAYERS member order", () => {
  const m = manifest();
  assert.equal("connector_inputs" in m, false);
  const steps = planSteps(m);
  assert.deepEqual(steps.map((s) => s.step_id), [
    "connectors:c1", "connectors:c2", "nodes:n1", "nodes:n2",
  ]);
  // No step gains binding metadata when nothing is declared.
  assert.deepEqual(steps.filter((s) => s.bindings).length, 0);
});

test("planSteps: a declared fetch is ordered ahead of the node it feeds", () => {
  const steps = planSteps(manifest({
    connector_inputs: [
      binding({ step_id: "b1", connector_id: "c2", feeds_node_id: "n1", feeds_param: "amount" }),
      binding({ step_id: "b2", connector_id: "c1", feeds_node_id: "n2", feeds_param: "rate" }),
    ],
  }));
  const at = (id) => steps.findIndex((s) => s.step_id === id);
  assert.ok(at("connectors:c2") < at("nodes:n1"));
  assert.ok(at("connectors:c1") < at("nodes:n2"));
  // Topology metadata reaches the consuming step for HELM-BIND-2, and carries
  // no resolved value.
  const n1 = steps[at("nodes:n1")];
  assert.deepEqual(n1.bindings, [
    { step_id: "b1", connector_id: "c2", feeds_param: "amount", from_step_id: "connectors:c2" },
  ]);
  assert.equal("value" in n1.bindings[0], false);
});

test("planSteps: seq stays the base index, and contentDigest is untouched by binding", () => {
  const declared = manifest({ connector_inputs: [binding()] });
  const plain = planSteps(manifest());
  const bound = planSteps(declared);
  for (const step of plain) {
    const same = bound.find((s) => s.step_id === step.step_id);
    assert.equal(same.contentDigest, step.contentDigest);
    assert.equal(same.seq, step.seq);
  }
});

test("orderStepsByEdges: stable — an unconstrained graph keeps base order", () => {
  const steps = ["a", "b", "c"].map((id, i) => ({ step_id: id, seq: i }));
  assert.deepEqual(orderStepsByEdges(steps, []).map((s) => s.step_id), ["a", "b", "c"]);
  assert.deepEqual(
    orderStepsByEdges(steps, [{ from: "c", to: "a" }]).map((s) => s.step_id),
    ["b", "c", "a"]
  );
  // A duplicate edge must not inflate indegree and strand the graph.
  assert.deepEqual(
    orderStepsByEdges(steps, [{ from: "c", to: "a" }, { from: "c", to: "a" }]).map((s) => s.step_id),
    ["b", "c", "a"]
  );
});

test("orderStepsByEdges: a cycle is rejected with a named error", () => {
  // NOTE: with today's vocabulary every edge runs connector -> node, so the
  // graph is bipartite and a cycle is structurally UNREACHABLE through a real
  // manifest. The detector is exercised here on synthetic edges so that stays
  // true by test rather than by assumption when later WUs add edge kinds.
  const steps = ["a", "b"].map((id, i) => ({ step_id: id, seq: i }));
  assert.throws(
    () => orderStepsByEdges(steps, [{ from: "a", to: "b" }, { from: "b", to: "a" }]),
    /manifest binding cycle/
  );
});

test("validation: connector_id absent from connectors[] is rejected", () => {
  assert.throws(
    () => validateManifestBindings(manifest({ connector_inputs: [binding({ connector_id: "nope" })] })),
    /absent from connectors\[\]/
  );
});

test("validation: feeds_node_id naming no node is rejected", () => {
  assert.throws(
    () => validateManifestBindings(manifest({ connector_inputs: [binding({ feeds_node_id: "n9" })] })),
    /matches no node in nodes\[\]/
  );
});

test("validation: a feeds_param the node does not accept is rejected", () => {
  const m = manifest();
  m.nodes[0].policy_parameters = { amount: 0 };
  assert.throws(
    () => validateManifestBindings({ ...m, connector_inputs: [binding({ feeds_param: "unknown_param" })] }),
    /does not accept/
  );
  // The declared param itself is accepted.
  validateManifestBindings({ ...m, connector_inputs: [binding()] });
});

test("validation: required_inputs[] widens a node's accepted parameter surface", () => {
  const m = manifest();
  m.nodes[0].policy_parameters = { amount: 0 };
  validateManifestBindings({
    ...m,
    required_inputs: [{ input_id: "i1", target_node_id: "n1", target_param: "rate" }],
    connector_inputs: [binding({ feeds_param: "rate" })],
  });
});

test("validation: a node declaring no parameter surface accepts any bound param", () => {
  // No policy_parameters, no required_inputs — the kernel registry declares no
  // param schema, so there is nothing to check against and the binding stands.
  validateManifestBindings(manifest({ connector_inputs: [binding({ feeds_param: "anything" })] }));
});

test("validation: duplicate connector_inputs step_id is rejected", () => {
  assert.throws(
    () => validateManifestBindings(manifest({
      connector_inputs: [binding(), binding({ connector_id: "c2", feeds_node_id: "n2" })],
    })),
    /duplicate connector_inputs step/
  );
});

test("validation runs BEFORE any write — a rejected manifest leaves no run and no journal entry", async () => {
  const db = dbAt("reject.db");
  await assert.rejects(
    executeRun(db, {
      runId: "run-bad",
      manifest: manifest({ connector_inputs: [binding({ connector_id: "nope" })] }),
      stepRunner: async () => {
        throw new Error("must not run — the manifest is invalid");
      },
    }),
    /absent from connectors\[\]/
  );
  const journalled = db.prepare("SELECT COUNT(*) AS c FROM journal").get().c;
  assert.equal(journalled, 0);
  const runs = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='runs'").get();
  assert.equal(runs, undefined, "a rejected manifest must not even create the runs table");
  db.close();
});

test("a valid binding executes fetch first; ctx still carries only digests (§2.5) — HELM-BIND-2 threads via step.resolvedParams instead", async () => {
  const db = dbAt("bound.db");
  const calls = [];
  const seenResolvedParams = [];
  const result = await executeRun(db, {
    runId: "run-bound",
    manifest: manifest({
      connector_inputs: [binding({ connector_id: "c2", feeds_node_id: "n1", feeds_param: "amount" })],
    }),
    stepRunner: async (step, ctx) => {
      assert.deepEqual(Object.keys(ctx).sort(), ["priorOutputDigest", "runId"]);
      calls.push(step.step_id);
      if (step.step_id === "nodes:n1") seenResolvedParams.push(step.resolvedParams);
      if (step.step_id === "connectors:c2") return { fetched: "c2-value" };
      return { ok: true, step_id: step.step_id };
    },
  });
  assert.equal(result.state, "completed");
  assert.ok(calls.indexOf("connectors:c2") < calls.indexOf("nodes:n1"));
  // §3.1: the bound node's step carries the producing step's output, keyed by
  // feeds_param — connector step is NOT invoked yet when planSteps() runs, but
  // by the time nodes:n1 is invoked, run.mjs has resolved it.
  assert.deepEqual(seenResolvedParams, [{ amount: { fetched: "c2-value" } }]);
  db.close();
});

// ---------------------------------------------------------------------------
// HELM-BIND-2 (§3): thread the resolved value into stepInputDigest and into
// the node's policy_parameters (kernel-runner.mjs covers the latter).
// ---------------------------------------------------------------------------

function connectorAwareStepRunner(outputByConnectorId) {
  return async (step) => {
    if (step.kind === "connectors" && step.item.connector_id in outputByConnectorId) {
      return outputByConnectorId[step.item.connector_id];
    }
    return { ok: true, step_id: step.step_id };
  };
}

test("§3.2: two runs of the same manifest on DIFFERENT connector data get DIFFERENT input_digests and no shared memo row", async () => {
  const db = dbAt("divergence.db");
  const m = manifest({
    connector_inputs: [binding({ connector_id: "c2", feeds_node_id: "n1", feeds_param: "amount" })],
  });

  const r1 = await executeRun(db, {
    runId: "run-a",
    manifest: m,
    stepRunner: connectorAwareStepRunner({ c2: { value: 100 } }),
  });
  const r2 = await executeRun(db, {
    runId: "run-b",
    manifest: m,
    stepRunner: connectorAwareStepRunner({ c2: { value: 999 } }),
  });

  const nodeStepA = r1.steps.find((s) => s.step_id === "nodes:n1");
  const nodeStepB = r2.steps.find((s) => s.step_id === "nodes:n1");
  assert.notEqual(nodeStepA.input_digest, nodeStepB.input_digest);
  assert.notEqual(r1.executionHash, r2.executionHash);

  const rows = db
    .prepare("SELECT DISTINCT input_digest FROM step_results WHERE step_id = 'nodes:n1'")
    .all();
  assert.equal(rows.length, 2, "different upstream data must NOT collide in the memo table");
  db.close();
});

test("§3.3: an unresolvable binding fails the step with a named error — never a silent {} fallback", async () => {
  const db = dbAt("unresolvable.db");
  const m = manifest({
    connector_inputs: [binding({ connector_id: "c2", feeds_node_id: "n1", feeds_param: "amount" })],
  });
  await assert.rejects(
    executeRun(db, {
      runId: "run-unresolvable",
      manifest: m,
      // The connector step's OWN runner throws, so it never produces an
      // output for stepOutputs to resolve nodes:n1's binding against.
      stepRunner: async (step) => {
        if (step.kind === "connectors") throw new Error("connector fetch failed (simulated)");
        return { ok: true, step_id: step.step_id };
      },
    }),
    /connector fetch failed \(simulated\)/
  );
  // The node step must never have run at all — no memo row exists for it.
  const nodeRows = db.prepare("SELECT COUNT(*) AS c FROM step_results WHERE step_id = 'nodes:n1'").get().c;
  assert.equal(nodeRows, 0);
  db.close();
});

test("§3.4: an unbound pack's execution_hash is unchanged before/after HELM-BIND-2 — quoted, not asserted", async () => {
  // No connector_inputs declared at all — resolveBoundParams must return null
  // for every step, so stepInputDigest's object shape (and hence every
  // digest) is bit-identical to the pre-HELM-BIND-2 formula.
  const db = dbAt("unbound-hash.db");
  const m = manifest(); // absent connector_inputs (§0.3)
  const result = await executeRun(db, {
    runId: "run-unbound",
    manifest: m,
    stepRunner: async (step) => ({ ok: true, step_id: step.step_id }),
  });
  assert.equal(result.state, "completed");
  // Measured directly against the pre-HELM-BIND-2 formula (HELM-BIND-1 @
  // 53dc303): this exact manifest + stepRunner produced this exact hash
  // BEFORE this WU's changes, and produces it again AFTER — bit-identical,
  // not merely "looks the same".
  assert.equal(
    result.executionHash,
    "sha256:ad591412cd082b4495e5da940956697e84c52321f6e2ffc73e861658f657f634"
  );
  db.close();
});

test("§0.3: an empty-array default WOULD move the digest — hence both members stay absent", () => {
  const plain = manifestDigest(manifest());
  assert.notEqual(manifestDigest(manifest({ connector_inputs: [] })), plain);
  assert.notEqual(manifestDigest(manifest({ required_inputs: [] })), plain);
  // And a manifest that declares no binding is digested exactly as before.
  assert.equal(manifestDigest(manifest()), plain);
});

test.after(() => rmSync(TMP, { recursive: true, force: true }));
