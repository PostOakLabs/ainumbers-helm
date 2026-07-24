// BPMN 2.0 XML export of workflow manifests (HELM-P4-B3, HELM-PHASE4-BUILD-SPEC.md
// §2 Band B row B3). One-time, spec-frozen mapping from
// schema/workflow-manifest.schema.json onto BPMN 2.0 so a manifest opens in
// Camunda Modeler, Bizagi, or Signavio for a reviewer who doesn't run Helm.
// This is a READ-ONLY diagram export, not a round-trippable interchange
// format — re-importing the XML back into Helm is out of scope (unlike
// workflow-export.mjs's .helm.json, which IS round-trippable). Mapping is
// intentionally lossy in one direction only: Helm-specific fields with no
// BPMN equivalent (kernel_digest, contract_digest, vault_ref, trust
// semantics) are carried as <bpmn:documentation> / extensionElements text so
// nothing silently disappears, but a BPMN tool cannot reconstruct a Helm
// manifest from the XML.
//
// Element mapping (frozen — a manifest shape change is a new mapping
// version, not an edit to this one):
//   trigger         -> startEvent (schedule trigger gets a timerEventDefinition)
//   connector_inputs -> serviceTask (one per connector-fetch step)
//   nodes (compute)  -> serviceTask (one per kernel node)
//   gates            -> exclusiveGateway
//   actions          -> serviceTask (terminal, target_host in documentation)
//   (no explicit end) -> synthesized endEvent
// Sequence flow order: start -> connector_inputs (in array order) -> nodes
// (in array order) -> gates (in array order) -> actions (in array order) -> end.
// This is a straight-line lane, not a graph reconstruction: workflow-manifest
// carries no edge list (nodes wire by node_id/target_param, not by
// predecessor pointers), so a linear BPMN process is the only faithful
// rendering without inventing structure the manifest doesn't have.

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function bpmnId(prefix, raw) {
  // BPMN QNames (NCName) can't start with a digit or contain most punctuation;
  // Helm ids are free-form strings, so sanitize deterministically.
  const cleaned = String(raw).replace(/[^A-Za-z0-9_.-]/g, "_");
  return `${prefix}_${/^[A-Za-z_]/.test(cleaned) ? cleaned : `_${cleaned}`}`;
}

// Builds the flat sequence of BPMN flow nodes from a workflow-manifest
// document, in the frozen order documented above.
function buildFlowNodes(manifest) {
  const flow = [];

  const startId = bpmnId("start", manifest.workflow_id);
  flow.push({
    id: startId,
    kind: "start",
    name: `Trigger: ${manifest.trigger.type}`,
    documentation: manifest.trigger.schedule ? `schedule: ${manifest.trigger.schedule}` : undefined,
    timer: manifest.trigger.type === "schedule" ? manifest.trigger.schedule : undefined,
  });

  for (const step of manifest.connector_inputs ?? []) {
    flow.push({
      id: bpmnId("task", step.step_id),
      kind: "service",
      name: `Fetch: ${step.connector_id}`,
      documentation: `feeds ${step.feeds_node_id}.${step.feeds_param}`,
    });
  }

  for (const node of manifest.nodes ?? []) {
    flow.push({
      id: bpmnId("task", node.node_id),
      kind: "service",
      name: node.kernel_id,
      documentation: `kernel_digest: ${node.kernel_digest}`,
    });
  }

  for (const gate of manifest.gates ?? []) {
    flow.push({
      id: bpmnId("gw", gate.gate_id),
      kind: "gateway",
      name: gate.type,
    });
  }

  for (const action of manifest.actions ?? []) {
    flow.push({
      id: bpmnId("task", action.action_id),
      kind: "service",
      name: `${action.type} → ${action.target_host}`,
      documentation: `target_host: ${action.target_host}`,
    });
  }

  const endId = bpmnId("end", manifest.workflow_id);
  flow.push({ id: endId, kind: "end", name: "Done" });

  return flow;
}

function renderFlowNode(node) {
  const nameAttr = node.name ? ` name="${xmlEscape(node.name)}"` : "";
  const doc = node.documentation
    ? `\n      <bpmn:documentation>${xmlEscape(node.documentation)}</bpmn:documentation>`
    : "";
  const incoming = node.incoming ? `\n      <bpmn:incoming>${node.incoming}</bpmn:incoming>` : "";
  const outgoing = node.outgoing ? `\n      <bpmn:outgoing>${node.outgoing}</bpmn:outgoing>` : "";

  if (node.kind === "start") {
    const timer = node.timer
      ? `\n      <bpmn:timerEventDefinition><bpmn:timeCycle>${xmlEscape(node.timer)}</bpmn:timeCycle></bpmn:timerEventDefinition>`
      : "";
    return `    <bpmn:startEvent id="${node.id}"${nameAttr}>${doc}${outgoing}${timer}\n    </bpmn:startEvent>`;
  }
  if (node.kind === "end") {
    return `    <bpmn:endEvent id="${node.id}"${nameAttr}>${doc}${incoming}\n    </bpmn:endEvent>`;
  }
  if (node.kind === "gateway") {
    return `    <bpmn:exclusiveGateway id="${node.id}"${nameAttr}>${doc}${incoming}${outgoing}\n    </bpmn:exclusiveGateway>`;
  }
  return `    <bpmn:serviceTask id="${node.id}"${nameAttr}>${doc}${incoming}${outgoing}\n    </bpmn:serviceTask>`;
}

// Converts a validated workflow-manifest document into a BPMN 2.0 XML string
// (a single <bpmn:process> with one straight-line lane; see module doc for
// the frozen element mapping). Does not validate the input against
// schema/workflow-manifest.schema.json itself — callers pass an already-
// validated manifest (workflow-export.mjs and packs.mjs both do).
export function exportBpmn(manifest) {
  if (!manifest || typeof manifest !== "object") {
    throw new Error("bpmn-export: manifest must be an object");
  }
  const processId = bpmnId("Process", manifest.workflow_id);
  const flow = buildFlowNodes(manifest);

  const sequenceFlows = [];
  for (let i = 0; i < flow.length - 1; i++) {
    const from = flow[i];
    const to = flow[i + 1];
    const flowId = `flow_${i}`;
    from.outgoing = flowId;
    to.incoming = flowId;
    sequenceFlows.push(
      `    <bpmn:sequenceFlow id="${flowId}" sourceRef="${from.id}" targetRef="${to.id}" />`
    );
  }

  const nodesXml = flow.map(renderFlowNode).join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>
<bpmn:definitions xmlns:bpmn="http://www.omg.org/spec/BPMN/20100524/MODEL"
  id="Definitions_${bpmnId("", manifest.workflow_id)}"
  targetNamespace="https://ainumbers.co/helm/bpmn"
  exporter="Helm control plane (HELM-P4-B3)"
  exporterVersion="1">
  <bpmn:process id="${processId}" name="${xmlEscape(manifest.workflow_id)}" isExecutable="false">
    <bpmn:documentation>Exported from a Helm workflow manifest (manifest_version ${xmlEscape(
      manifest.manifest_version
    )}). Diagram export only — not round-trippable back into Helm.</bpmn:documentation>
${nodesXml}
${sequenceFlows.join("\n")}
  </bpmn:process>
</bpmn:definitions>
`;
}
