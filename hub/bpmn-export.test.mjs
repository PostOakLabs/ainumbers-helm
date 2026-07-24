import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { exportBpmn } from "./bpmn-export.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN = JSON.parse(
  readFileSync(join(HERE, "..", "fixtures", "workflow-manifest", "golden.json"), "utf8")
);

function ids(xml, tag) {
  const re = new RegExp(`<bpmn:${tag} id="([^"]+)"`, "g");
  const out = [];
  let m;
  while ((m = re.exec(xml))) out.push(m[1]);
  return out;
}

test("exportBpmn produces well-formed XML with matching open/close tag counts", () => {
  const xml = exportBpmn(GOLDEN);
  assert.match(xml, /^<\?xml version="1.0" encoding="UTF-8"\?>/);
  for (const tag of ["startEvent", "endEvent", "serviceTask", "exclusiveGateway", "sequenceFlow", "process", "definitions"]) {
    const opens = (xml.match(new RegExp(`<bpmn:${tag}[ >]`, "g")) ?? []).length;
    const selfClosing = (xml.match(new RegExp(`<bpmn:${tag}[^>]*/>`, "g")) ?? []).length;
    const closes = (xml.match(new RegExp(`</bpmn:${tag}>`, "g")) ?? []).length;
    assert.equal(opens - selfClosing, closes, `${tag}: ${opens} opens (${selfClosing} self-closing) vs ${closes} closes`);
  }
});

test("exportBpmn emits one flow node per manifest element plus synthesized start/end", () => {
  const xml = exportBpmn(GOLDEN);
  const expectedCount =
    1 + // start
    (GOLDEN.connector_inputs?.length ?? 0) +
    GOLDEN.nodes.length +
    GOLDEN.gates.length +
    GOLDEN.actions.length +
    1; // end
  const taskIds = ids(xml, "startEvent").length +
    ids(xml, "endEvent").length +
    ids(xml, "serviceTask").length +
    ids(xml, "exclusiveGateway").length;
  assert.equal(taskIds, expectedCount);
});

test("exportBpmn sequence flows form one straight-line chain with no dangling refs", () => {
  const xml = exportBpmn(GOLDEN);
  const nodeIds = new Set([
    ...ids(xml, "startEvent"),
    ...ids(xml, "endEvent"),
    ...ids(xml, "serviceTask"),
    ...ids(xml, "exclusiveGateway"),
  ]);
  const flowRe = /<bpmn:sequenceFlow id="[^"]+" sourceRef="([^"]+)" targetRef="([^"]+)" \/>/g;
  let m;
  let count = 0;
  while ((m = flowRe.exec(xml))) {
    assert.ok(nodeIds.has(m[1]), `sourceRef ${m[1]} must be a real flow node`);
    assert.ok(nodeIds.has(m[2]), `targetRef ${m[2]} must be a real flow node`);
    count++;
  }
  assert.equal(count, nodeIds.size - 1, "a straight-line chain has exactly n-1 flows for n nodes");
});

test("exportBpmn carries kernel_digest and connector/action detail in documentation, never drops them silently", () => {
  const xml = exportBpmn(GOLDEN);
  for (const node of GOLDEN.nodes) {
    assert.ok(xml.includes(node.kernel_digest), `kernel_digest ${node.kernel_digest} must survive export`);
  }
  for (const action of GOLDEN.actions) {
    assert.ok(xml.includes(action.target_host), `action target_host ${action.target_host} must survive export`);
  }
});

test("exportBpmn escapes XML-special characters in ids and names", () => {
  const manifest = {
    ...GOLDEN,
    workflow_id: `wf<"&'>weird`,
    trigger: { type: "manual" },
    connector_inputs: [],
  };
  const xml = exportBpmn(manifest);
  assert.doesNotMatch(xml, /name="wf<"/);
  assert.match(xml, /name="wf&lt;&quot;&amp;&apos;&gt;weird"/);
});

test("exportBpmn handles a manifest with no gates/actions/connector_inputs (start -> node -> end only)", () => {
  const minimal = {
    manifest_version: "1",
    workflow_id: "wf-minimal",
    trigger: { type: "manual" },
    nodes: [{ node_id: "n1", kernel_id: "art-1", kernel_digest: `sha256:${"a".repeat(64)}` }],
    connectors: [],
    gates: [],
    actions: [],
  };
  const xml = exportBpmn(minimal);
  assert.equal((xml.match(/<bpmn:sequenceFlow/g) ?? []).length, 2);
});

test("exportBpmn throws on a non-object manifest instead of silently producing empty XML", () => {
  assert.throws(() => exportBpmn(null));
  assert.throws(() => exportBpmn("not an object"));
});
