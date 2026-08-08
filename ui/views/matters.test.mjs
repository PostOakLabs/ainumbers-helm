// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Pure-function tests for the Matters view (HELM-MATTER-U1). matterCard is
// daemon-data-in, HTML-string-out — same convention as connect.test.mjs's
// connectorCard tests — so these run under plain node:test with no DOM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { matterCard, filterMatters, sortDeadlines, nextOpenDeadline, bindingKindBadge } from "./matters.mjs";

const HOSTILE = `</code><img src=x onerror=alert(document.domain)>`;

function baseMatter(overrides = {}) {
  return {
    matter_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    status: "working",
    entity: { id: "did:key:zExampleEntity" },
    parties: [],
    deadlines: [],
    bindings: [],
    created_at: "2026-08-01T00:00:00.000Z",
    updated_at: "2026-08-01T00:00:00.000Z",
    manifest_digest: "sha256:" + "a".repeat(64),
    ...overrides,
  };
}

test("matterCard: hostile fields never reach the DOM unescaped", () => {
  const html = matterCard(
    baseMatter({
      entity: { id: HOSTILE },
      narrative: HOSTILE,
      parties: [{ identity: { id: HOSTILE }, role: HOSTILE }],
      deadlines: [{ date: "2026-09-01", action: HOSTILE, type: HOSTILE, source: HOSTILE, done: false }],
      bindings: [{ subject_hash: "sha256:" + "b".repeat(64), subject_kind: "run", note: HOSTILE }],
    })
  );
  assert.ok(!html.includes("<img"), "raw <img> tag leaked into markup");
  assert.ok(html.includes("&lt;/code&gt;"), "hostile string was not escaped");
  assert.ok(html.includes("&lt;img"), "the hostile tag must survive only in escaped form");
});

test("matterCard: well-formed matter renders its core fields", () => {
  const html = matterCard(
    baseMatter({
      entity: { id: "did:key:zAcme", lei: "5493001KJTIIGC8Y1R12" },
      parties: [{ identity: { id: "did:key:zExaminer" }, role: "examiner" }],
    })
  );
  assert.ok(html.includes("did:key:zAcme"));
  assert.ok(html.includes("5493001KJTIIGC8Y1R12"));
  assert.ok(html.includes("examiner"));
  assert.ok(html.includes("01ARZ3NDEKTSV4RRFFQ69G5FAV"));
});

// The load-bearing requirement: external_reference must never share a badge
// or a "verified" claim with the four locally-resolving kinds.
test("bindingKindBadge: external_reference is visually and textually distinct from a local kind", () => {
  const external = bindingKindBadge("external_reference");
  const local = bindingKindBadge("run");
  assert.ok(external.includes('data-kind="external"'));
  assert.ok(local.includes('data-kind="local"'));
  assert.notEqual(external, local, "external and local badges must render differently");
  assert.ok(!external.toLowerCase().includes(">verified<"), "external badge must never render as a bare \"verified\" label");
});

for (const kind of ["run", "evidence_bundle", "approval_record", "attested_artifact"]) {
  test(`bindingKindBadge: ${kind} is labeled with its real kind, not a generic verified badge`, () => {
    const badge = bindingKindBadge(kind);
    assert.ok(badge.includes(`>${kind}<`), `badge text must be the real subject_kind ("${kind}")`);
    assert.ok(badge.includes('data-kind="local"'));
  });
}

test("matterCard: a matter with an external_reference binding never collapses it into the same badge as a local binding", () => {
  const html = matterCard(
    baseMatter({
      bindings: [
        { subject_hash: "sha256:" + "c".repeat(64), subject_kind: "run" },
        { subject_hash: "sha256:" + "d".repeat(64), subject_kind: "external_reference" },
      ],
    })
  );
  assert.ok(html.includes('data-kind="local"'));
  assert.ok(html.includes('data-kind="external"'));
  assert.ok(html.includes("never verified by Helm"), "external_reference binding must carry its own never-verified note");
  assert.ok(html.includes("1 of 2 bindings is external_reference"));
});

test("sortDeadlines: open deadlines surface before done ones, done ones stay present", () => {
  const deadlines = [
    { date: "2026-01-01", action: "already filed", type: "filing", source: "reg", done: true, done_at: "2026-01-01T00:00:00Z" },
    { date: "2026-12-01", action: "still open", type: "filing", source: "reg", done: false },
  ];
  const sorted = sortDeadlines(deadlines);
  assert.equal(sorted.length, 2, "a done:true deadline must never be dropped");
  assert.equal(sorted[0].action, "still open", "the open deadline must surface first");
  assert.equal(sorted[1].action, "already filed");
});

test("nextOpenDeadline: picks the earliest open deadline, ignores done ones", () => {
  const deadlines = [
    { date: "2026-03-01", action: "later open", type: "x", source: "y", done: false },
    { date: "2026-01-15", action: "earlier open", type: "x", source: "y", done: false },
    { date: "2026-01-01", action: "already done", type: "x", source: "y", done: true },
  ];
  assert.equal(nextOpenDeadline(deadlines).action, "earlier open");
});

test("nextOpenDeadline: null when every deadline is done or there are none", () => {
  assert.equal(nextOpenDeadline([]), null);
  assert.equal(nextOpenDeadline([{ date: "2026-01-01", action: "done", type: "x", source: "y", done: true }]), null);
});

test("matterCard: a matter closing with an open deadline still surfaces it unredacted", () => {
  const html = matterCard(
    baseMatter({
      status: "closed",
      deadlines: [{ date: "2026-12-01", action: "post-closure filing", type: "filing", source: "reg", done: false }],
    })
  );
  assert.ok(html.includes("Next open deadline"));
  assert.ok(html.includes("post-closure filing"));
});

test("filterMatters: open excludes closed, closed excludes everything else, all keeps everything", () => {
  const matters = [baseMatter({ matter_id: "A".repeat(26), status: "intake" }), baseMatter({ matter_id: "B".repeat(26), status: "working" }), baseMatter({ matter_id: "C".repeat(26), status: "closed" })];
  assert.deepEqual(
    filterMatters(matters, "open").map((m) => m.status),
    ["intake", "working"]
  );
  assert.deepEqual(
    filterMatters(matters, "closed").map((m) => m.status),
    ["closed"]
  );
  assert.equal(filterMatters(matters, "all").length, 3);
});
