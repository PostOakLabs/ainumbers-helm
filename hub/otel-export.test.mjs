// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-OTEL-1 — otel-export.mjs: OTLP-JSON GenAI span tree per helm run.
// Covered: span count = completed steps; invoke_agent carries
// run_id/workflow_id/composite execution hash; execute_tool carries
// execution_hash + kernel_digest per completed step; a failed run yields an
// error-status invoke_agent with NO execute_tool for unexecuted steps; no
// POST when config.otelCollectorUrl is empty (fetch stub asserts zero calls);
// a set collector URL POSTs exactly once through performEgress (whose
// DNS-rebind guard refuses loopback collectors); the vendored
// lintOtlpTrace accepts the completed-run document; attribute names stay
// pinned to hub/fixtures/otel-attributes.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TMP = mkdtempSync(join(tmpdir(), "helm-otel-export-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("./journal.mjs");
const { executeRun } = await import("./run.mjs");
const { buildRunOtlpTrace, recordRunSpans } = await import("./otel-export.mjs");
const { lintOtlpTrace } = await import("../hub/vendored/worker-otelspan/otelspan.mjs");

function manifest(overrides = {}) {
  return {
    manifest_version: "1",
    workflow_id: "wf-otel-export-test-01",
    trigger: { type: "schedule", schedule: "0 6 * * *" },
    nodes: [
      { node_id: "n1", kernel_id: "art-213-fee-route" },
      { node_id: "n2", kernel_id: "art-214-variance-check" },
      { node_id: "n3", kernel_id: "art-215-shortsale-monitor" },
    ],
    connectors: [],
    gates: [],
    actions: [],
    ...overrides,
  };
}

// Kernel-artifact-shaped step output: what kernel-runner.mjs actually returns
// (trust_label/kernel_id/kernel_digest/artifact with a root execution_hash).
function kernelOutput(step, i) {
  return {
    trust_label: "kernel_verified",
    kernel_id: `art-${210 + i}`,
    kernel_digest: `sha256:${String(i).padStart(64, "0")}`,
    artifact: {
      tool_id: `art-${210 + i}`,
      execution_hash: `sha256:step-${step.step_id}`,
    },
  };
}

function dbAt(name) {
  return openJournal(join(TMP, name));
}

function flatSpans(trace) {
  const out = [];
  for (const rs of trace.resourceSpans ?? []) {
    for (const ss of rs.scopeSpans ?? []) out.push(...(ss.spans ?? []));
  }
  return out;
}

function attrMap(span) {
  const m = {};
  for (const a of span.attributes ?? []) m[a.key] = a.value?.stringValue ?? a.value?.intValue;
  return m;
}

async function completedRun(db, runId) {
  return await executeRun(db, {
    runId,
    manifest: manifest(),
    stepRunner: async (step, { runId: r }) => kernelOutput(step, [...step.step_id].length),
  });
}

test("otel-export: completed run — span count equals completed steps, vendored linter accepts the doc, fixture pins attribute names", async () => {
  const db = dbAt("otel-completed.db");
  await completedRun(db, "run-otel-ok");

  const { trace, state } = buildRunOtlpTrace(db, "run-otel-ok");
  assert.equal(state, "completed");
  const spans = flatSpans(trace);
  assert.equal(spans.length, 3 + 1); // one execute_tool per completed step + one invoke_agent root
  assert.equal(spans.filter((s) => attrMap(s)["gen_ai.operation.name"] === "execute_tool").length, 3);

  // Root
  const roots = spans.filter((s) => !s.parentSpanId);
  assert.equal(roots.length, 1);
  const root = roots[0];
  const rootAttrs = attrMap(root);
  assert.equal(rootAttrs["gen_ai.operation.name"], "invoke_agent");
  assert.equal(rootAttrs["gen_ai.agent.name"], "wf-otel-export-test-01");
  assert.equal(rootAttrs["ocg.run_id"], "run-otel-ok");
  assert.ok(rootAttrs["ocg.workflow_id"]);
  assert.ok(rootAttrs["ocg.composite_execution_hash"]);
  assert.match(spans[0].traceId, /^[0-9a-f]{32}$/);
  assert.match(spans[0].spanId, /^[0-9a-f]{16}$/);

  // Per-step span: every completed step carries execution_hash + kernel_digest
  const toolSpans = spans.filter((s) => attrMap(s)["gen_ai.operation.name"] === "execute_tool");
  for (const t of toolSpans) {
    const attrs = attrMap(t);
    assert.equal(attrs["gen_ai.system"], "ainumbers-helm");
    assert.ok(attrs["gen_ai.tool.name"]);
    assert.ok(String(attrs["ocg.run_id"]) === "run-otel-ok");
    assert.ok(t.parentSpanId === root.spanId);
    assert.equal(attrs["ocg.execution_hash"]?.startsWith("sha256:step-") ?? attrs["ocg.execution_hash"], true);
    assert.equal(String(attrs["ocg.kernel_digest"]).startsWith("sha256:"), true);
  }

  // The vendored worker linter accepts the document (structural conformance).
  const lint = lintOtlpTrace({ resourceSpans: trace.resourceSpans });
  assert.equal(lint.findings.filter((f) => f.ok === false).length, 0);

  // Attribute-name pin (hub/fixtures/otel-attributes.json)
  const fixture = JSON.parse(readFileSync(new URL("./fixtures/otel-attributes.json", import.meta.url), "utf8"));
  assert.equal(fixture.execute_tool_span.filter((k) => k === "ocg.run_id").length, 1);
  assert.equal(fixture.invoke_agent_span.filter((k) => k === "ocg.workflow_id").length, 1);
  const allUsed = new Set(flatSpans(trace).flatMap((s) => (s.attributes ?? []).map((a) => a.key)));
  for (const k of allUsed) {
    assert.ok(
      fixture.invoke_agent_span.includes(k) || fixture.execute_tool_span.includes(k) || fixture.resource.includes(k),
      `unpinned attribute name "${k}"`
    );
  }
  db.close();
});

test("otel-export: failed run — invoke_agent carries an error status, no execute_tool span for unexecuted steps", async () => {
  const db = dbAt("otel-failed.db");
  await assert.rejects(
    executeRun(db, {
      runId: "run-otel-failed",
      manifest: manifest(),
      stepRunner: async (step) => {
        if (step.step_id === "nodes:n2") throw new Error("simulated failure");
        return kernelOutput(step, [...step.step_id].length);
      },
    })
  );

  const { trace, state } = buildRunOtlpTrace(db, "run-otel-failed");
  assert.equal(state, "failed");
  const spans = flatSpans(trace);
  assert.equal(spans.filter((s) => attrMap(s)["gen_ai.operation.name"] === "execute_tool").length, 1); // only n1 completed
  const root = spans.find((s) => !s.parentSpanId);
  assert.equal(attrMap(root)["gen_ai.operation.name"], "invoke_agent");
  assert.equal(root.status?.code, "STATUS_CODE_ERROR");
  assert.match(root.status?.message ?? "", /ended in state: failed/);
  db.close();
});

test("otel-export: recordRunSpans writes <state-dir>/otel/<run_id>.json by default and never POSTs while the collector URL is empty", async () => {
  const db = dbAt("otel-write.db");
  await completedRun(db, "run-otel-write");

  let postCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    postCalls += 1;
    return originalFetch;
  };
  try {
    await recordRunSpans(db, "run-otel-write", { now: "2026-09-09T00:00:00Z" });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(postCalls, 0, "an empty config.otelCollectorUrl must produce zero collector POSTs");

  const written = JSON.parse(readFileSync(join(TMP, "otel", "run-otel-write.json"), "utf8"));
  assert.equal(Array.isArray(written.resourceSpans), true);
  db.close();
});

test("otel-export: fetch default-off belt-and-suspenders — recordRunSpans with an empty collector URL never egresses", async () => {
  const db = dbAt("otel-nopost.db");
  await completedRun(db, "run-otel-nopost");
  let postCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("collector")) postCalls += 1;
    return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(0), headers: { get: () => null } };
  };
  try {
    await recordRunSpans(db, "run-otel-nopost", { now: "2026-09-09T00:00:00Z" });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(postCalls, 0);
  db.close();
});

test("otel-export: a configured collector URL POSTs exactly once through performEgress — and a loopback collector is refused by the same guard", async () => {
  // Own HOME clone so the collector-URL config here cannot touch other tests.
  const { writeFileSync } = await import("node:fs");
  const alt = mkdtempSync(join(tmpdir(), "helm-otel-config-test-"));
  process.env.HELM_HOME = alt;
  // TEST-NET-3 literal IP: public-side, non-denied by the guard, and never
  // dialed for real because the fetch stub below intercepts first. A
  // HOSTNAME collector would need a real DNS lookup, which no helm test may
  // require (offline-runnable suite).
  writeFileSync(join(alt, "config.json"), JSON.stringify({ otelCollectorUrl: "http://203.0.113.10:4318/v1/traces" }));
  const { loadConfig } = await import("./config.mjs");
  assert.equal(loadConfig().otelCollectorUrl, "http://203.0.113.10:4318/v1/traces");

  const db = dbAt("otel-post.db");
  let posts = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    posts += 1;
    const doc = JSON.parse(String(opts.body));
    assert.match(String(url), /203\.0\.113\.10:4318\/v1\/traces/);
    assert.equal(Array.isArray(doc.resourceSpans), true);
    assert.equal(String(opts.headers["content-type"]).includes("application/json"), true);
    return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(0), headers: { get: () => null } };
  };
  try {
    // The run finalisation hook itself performs the (stubbed) POST.
    await completedRun(db, "run-otel-post");
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(posts, 1, "a configured collector is dialed exactly once per run");
  assert.equal(existsSync(join(alt, "otel", "run-otel-post.json")), true, "the OTLP-JSON file is written regardless of the collector");

  // A loopback collector is refused by the SAME guard (documented posture):
  // swap to a loopback URL and assert zero collector dials of any kind.
  const alt2 = mkdtempSync(join(tmpdir(), "helm-otel-loopback-test-"));
  process.env.HELM_HOME = alt2;
  writeFileSync(join(alt2, "config.json"), JSON.stringify({ otelCollectorUrl: "http://127.0.0.1:4318/v1/traces" }));
  const db2 = dbAt("otel-loopback.db");
  let posts2 = 0;
  globalThis.fetch = async () => {
    posts2 += 1;
    return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(0), headers: { get: () => null } };
  };
  try {
    // recordRunSpans swallows the guard's refusal (never fails a run) — the
    // observable contract is that NOTHING was dialed and the local file
    // still exists.
    await completedRun(db2, "run-otel-loopback");
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(posts2, 0, "a loopback collector is refused before any fetch happens (EGRESS guard, no carve-out)");
  assert.equal(existsSync(join(alt2, "otel", "run-otel-loopback.json")), true, "the local OTLP-JSON file still exists after a refused POST");
  db.close();
  db2.close();
  process.env.HELM_HOME = TMP;
  rmSync(alt, { recursive: true, force: true });
  rmSync(alt2, { recursive: true, force: true });
});

test("otel-export: a run still awaiting_data (never finalised) yields no document", async () => {
  const db = dbAt("otel-held.db");
  await executeRun(db, {
    runId: "run-otel-held",
    manifest: manifest(),
    gateCheck: async (step) => (step.step_id === "nodes:n1" ? { held: true, reason: "human approval" } : null),
    stepRunner: async (step) => kernelOutput(step, 1),
  });
  const { trace } = buildRunOtlpTrace(db, "run-otel-held");
  assert.equal(trace, null, "a run that is not terminal (completed/failed) is not yet finalised — no span doc");
  db.close();
});
