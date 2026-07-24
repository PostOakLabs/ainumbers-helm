// EUC register entry + kernel validation card generator (HELM-P3-E12,
// HELM-PHASE3-BUILD-SPEC.md §3 item 5). Turns SR 11-7/SS1-23 model-risk
// paperwork into a one-click export instead of manual spreadsheet upkeep —
// generated entirely from already-vendored kernel metadata + committed
// fixtures (D2 zero-dep: no new persistence, no live kernel execution).
//
// Scope note: owner/purpose/control_description/last_validated aren't
// tracked anywhere in helm today (confirmed — no workflow record carries
// them). Rather than invent a new persisted table for a Phase-3 WU, this
// module accepts them as caller-supplied fields at export time and composes
// them with the pack's existing name/outcome/manifest.nodes. If Tim wants
// these durable across sessions, that's a follow-up WU adding a small
// journal stream, not a schema change here.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { getPack } from "./packs.mjs";
import { pinnedKernelDigest } from "./kernel-runner.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDORED = join(HERE, "vendored", "ocg");

let chaingraphCache = null;
function loadChaingraph() {
  if (chaingraphCache) return chaingraphCache;
  const g = JSON.parse(readFileSync(join(VENDORED, "chaingraph.json"), "utf8"));
  chaingraphCache = new Map(g.nodes.map((n) => [n.tool_id, n]));
  return chaingraphCache;
}

function loadFixtures(kernelId) {
  const path = join(VENDORED, "kernels", "fixtures", `${kernelId}.fixtures.json`);
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null; // ABSENCE-INSTRUMENT: caller decides how to surface "no fixtures vendored"
  }
}

// Per-kernel validation card: formula/description, source ref, version hash,
// test vectors + expected outputs, replay instructions — everything an
// SR 11-7 model-validation reviewer needs to independently re-derive the
// kernel's behavior without running Helm.
export function buildKernelCard(kernelId, { now } = {}) {
  const node = loadChaingraph().get(kernelId);
  if (!node) throw new Error(`euc-register: unknown kernel_id "${kernelId}" (not in vendored chaingraph.json)`);

  const digest = pinnedKernelDigest(kernelId);
  const fixtures = loadFixtures(kernelId);
  const vectors = fixtures?.vectors ?? [];

  return {
    kernel_id: kernelId,
    tool_version: node.tool_version ?? null,
    display_name: node.display_name ?? kernelId,
    description: node.description ?? "",
    source_url: node.url ?? null,
    kernel_digest: digest,
    conformance_fixtures_vendored: fixtures !== null,
    test_vectors: vectors.map((v) => ({
      name: v.name,
      policy_parameters: v.policy_parameters,
      expected_output_payload: v.output_payload,
      expected_execution_hash: v.golden_hash,
    })),
    replay_instructions:
      "1) Load kernel " + kernelId + ".kernel.mjs from the pinned vendored copy (digest above). " +
      "2) Call its exported compute()/buildArtifact() with a test vector's policy_parameters. " +
      "3) Confirm the returned output_payload matches expected_output_payload and its recomputed execution hash matches expected_execution_hash. " +
      "A mismatch means the running kernel is not the version this card certifies.",
    generated_at: now ?? new Date().toISOString(),
  };
}

// The last node in a compiled pack's manifest.nodes is its output boundary —
// every shipped pack today is a linear kernel-DAG with empty
// connectors/gates/actions (compile-packs.mjs's DEC-4 triage), so "last node
// in emission order" is an honest terminus, not a guess. A future non-linear
// pack would need a real graph-terminus computation; this module does not
// attempt one (ABSENCE-INSTRUMENT: flagged here, not silently assumed away).
function terminalNode(manifest) {
  const nodes = manifest.nodes ?? [];
  return nodes.length ? nodes[nodes.length - 1] : null;
}

// One-click EUC register entry for a workflow: name, owner, purpose, every
// kernel version+hash the workflow pins, declared inputs/outputs, control
// description, last-validated date — the exact shape a compliance officer's
// EUC register spreadsheet wants, generated instead of hand-maintained.
export function buildEucEntry(workflowId, { owner, purpose, controlDescription, lastValidated, now } = {}) {
  const pack = getPack(workflowId);
  if (!pack) throw new Error(`euc-register: unknown workflow_id "${workflowId}" (not a compiled pack)`);

  const nodes = pack.manifest.nodes ?? [];
  const terminal = terminalNode(pack.manifest);

  return {
    workflow_id: pack.workflow_id,
    name: pack.name,
    owner: owner ?? null,
    purpose: purpose ?? pack.outcome ?? null,
    control_description: controlDescription ?? null,
    last_validated: lastValidated ?? null,
    kernels: nodes.map((n) => ({
      node_id: n.node_id,
      kernel_id: n.kernel_id,
      kernel_digest: n.kernel_digest,
    })),
    declared_inputs: pack.declared_inputs ?? [],
    declared_outputs: terminal
      ? [{ node_id: terminal.node_id, kernel_id: terminal.kernel_id, note: "terminal node of a linear compiled chain" }]
      : [],
    workflow_manifest_digest: pack.workflow_manifest_digest,
    generated_at: now ?? new Date().toISOString(),
  };
}
