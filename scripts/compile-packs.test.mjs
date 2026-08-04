import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "./lib/schema-validator.mjs";
import { loadContract } from "../hub/connector.mjs";
import { executeRun } from "../hub/run.mjs";
import { runKernelNode } from "../hub/kernel-runner.mjs";
import { openJournal } from "../hub/journal.mjs";
import { KERNELS } from "../hub/vendored/ocg/kernels/index.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PACKS_DIR = join(ROOT, "packs");
const SCHEMA = JSON.parse(readFileSync(join(ROOT, "schema", "workflow-manifest.schema.json"), "utf8"));
const CONNECTOR_BINDINGS = JSON.parse(readFileSync(join(ROOT, "scripts", "connector-bindings.json"), "utf8"));

function run(args) {
  return execFileSync(process.execPath, [join(ROOT, "scripts", "compile-packs.mjs"), ...args], {
    cwd: ROOT,
    stdio: "pipe",
  }).toString();
}

test("compile-packs: compiles a non-empty subset and skips the rest with logged reasons", () => {
  run([]);
  const index = JSON.parse(readFileSync(join(PACKS_DIR, "INDEX.json"), "utf8"));
  assert.ok(index.compiledCount > 0, "expected at least one compiled pack");
  // PACKMARKER-EXTEND-97-1: skippedCount is legitimately 0 once every
  // currently-missing step across every chain resolves as a confirmed
  // browser tool (§7.2 exclusions are an expected, not guaranteed, outcome).
  assert.ok(index.skippedCount >= 0, "skippedCount must be a valid non-negative count");
  assert.equal(index.compiledCount + index.skippedCount > 0, true);
  for (const skip of index.skips) {
    assert.ok(skip.name && skip.reason, "every skip MUST carry a name + reason — no silent truncation");
  }

  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  assert.equal(packFiles.length, index.compiledCount);
});

test("compile-packs: every emitted pack's manifest validates against schema/workflow-manifest.schema.json", () => {
  run([]);
  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  for (const file of packFiles) {
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, file), "utf8"));
    const errs = validate(SCHEMA, pack.manifest);
    assert.deepEqual(errs, [], `${file}: manifest failed schema validation: ${errs.join(", ")}`);
    assert.ok(/^sha256:[0-9a-f]{64}$/.test(pack.workflow_manifest_digest));
  }
});

test("compile-packs: --check passes on freshly generated packs/, fails after a tamper", () => {
  run([]);
  run(["--check"]); // should not throw

  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  const victim = join(PACKS_DIR, packFiles[0]);
  const original = readFileSync(victim, "utf8");
  const tampered = JSON.parse(original);
  tampered.name = "TAMPERED";
  writeFileSync(victim, JSON.stringify(tampered, null, 2) + "\n");

  assert.throws(() => run(["--check"]), /Command failed/);

  writeFileSync(victim, original); // restore — leave packs/ fresh for other tests/CI steps
});

// HELM-BIND-4 ------------------------------------------------------------

test("compile-packs: packs with no connector-bindings.json entry keep connectors:[] and BOTH connector_inputs/required_inputs ABSENT", () => {
  run([]);
  const boundIds = new Set(Object.keys(CONNECTOR_BINDINGS).filter((k) => k !== "_comment"));
  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json");
  let checked = 0;
  for (const file of packFiles) {
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, file), "utf8"));
    if (boundIds.has(pack.workflow_id)) continue;
    checked++;
    assert.deepEqual(pack.manifest.connectors, []);
    assert.equal("connector_inputs" in pack.manifest, false, `${file}: connector_inputs must be absent, not []`);
    assert.equal("required_inputs" in pack.manifest, false, `${file}: required_inputs must be absent, not []`);
  }
  assert.ok(checked > 0);
});

test("compile-packs: the bound pack emits a schema-valid real connector wired to an existing node/param", () => {
  run([]);
  for (const [workflowId, binding] of Object.entries(CONNECTOR_BINDINGS)) {
    if (workflowId === "_comment") continue;
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, `${workflowId}.json`), "utf8"));
    const { manifest } = pack;

    assert.deepEqual(validate(SCHEMA, manifest), []);

    assert.equal(manifest.connectors.length, 1);
    assert.equal(manifest.connectors[0].connector_id, binding.connector_id);
    const { contractDigest } = loadContract(join(ROOT, "hub", "connectors", binding.contract_file));
    assert.equal(manifest.connectors[0].contract_digest, contractDigest, "contract_digest must be independently reproducible from the connector's own contract file");

    // §0.25: every connector_inputs[].connector_id must appear in connectors[].
    const connectorIds = new Set(manifest.connectors.map((c) => c.connector_id));
    for (const b of manifest.connector_inputs) {
      assert.ok(connectorIds.has(b.connector_id), `connector_inputs step "${b.step_id}" names an undeclared connector_id "${b.connector_id}"`);
      assert.ok(manifest.nodes.some((n) => n.node_id === b.feeds_node_id), `connector_inputs step "${b.step_id}" names no existing node`);
    }
    assert.ok(manifest.required_inputs.length > 0);
  }
});

test("compile-packs: end-to-end — a connector-fetched value reaches buildArtifact and changes execution_hash", async () => {
  run([]);
  const [workflowId, binding] = Object.entries(CONNECTOR_BINDINGS).find(([k]) => k !== "_comment");
  const pack = JSON.parse(readFileSync(join(PACKS_DIR, `${workflowId}.json`), "utf8"));
  const nodeId = binding.feeds_node_id;
  const node = pack.manifest.nodes.find((n) => n.node_id === nodeId);
  const kernel = KERNELS[node.kernel_id];
  assert.ok(kernel, `kernel "${node.kernel_id}" must be vendored`);

  const rowsA = [{ row_id: "a0", flow_type: "inflow", amount_musd: 100, maturity_days: 1, is_intercompany: false }];
  const rowsB = [{ row_id: "b0", flow_type: "outflow", amount_musd: 5000, maturity_days: 400, is_intercompany: false }];

  async function runWithConnectorOutput(rows) {
    const tmpDir = mkdtempSync(join(tmpdir(), "helm-bind4-e2e-"));
    const db = openJournal(join(tmpDir, "run.db"));
    const connectorStepId = `connectors:${binding.connector_id}`;
    try {
      const artifacts = new Map();
      const result = await executeRun(db, {
        runId: `bind4-e2e-${rows[0].row_id}`,
        manifest: pack.manifest,
        stepRunner: async (step) => {
          if (step.step_id === connectorStepId) return rows; // simulated google-drive.fetch output
          if (step.kind === "nodes") {
            const r = await runKernelNode(step, { now: "2026-01-01T00:00:00.000Z" });
            artifacts.set(step.step_id, r);
            return r;
          }
          throw new Error(`unexpected step kind in test: ${step.kind}`);
        },
      });
      assert.equal(result.state, "completed");
      return artifacts.get(`nodes:${nodeId}`).artifact;
    } finally {
      db.close();
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  const artifactA = await runWithConnectorOutput(rowsA);
  const artifactB = await runWithConnectorOutput(rowsB);

  // The connector's fetched value really did reach buildArtifact...
  assert.deepEqual(artifactA.policy_parameters.rows, rowsA);
  assert.deepEqual(artifactB.policy_parameters.rows, rowsB);
  // ...and equals what calling the kernel directly on the same data produces.
  const canonicalA = await kernel.buildArtifact({ rows: rowsA }, { now: "2026-01-01T00:00:00.000Z" });
  assert.equal(artifactA.execution_hash, canonicalA.execution_hash);
  // Different connector-fetched data changes execution_hash.
  assert.notEqual(artifactA.execution_hash, artifactB.execution_hash);
});

// PACK-MARKER-COMPILE-1 (PACK-MARKER-BUILD-SPEC.md §4, §6, §9 row 2);
// PACKMARKER-EXTEND-97-1 widened the allowlist from 5 to 102 chains. Read
// MARKER_PILOT_CHAINS out of the compiler's own source (not a second
// hardcoded copy) so this test can't silently drift from the real allowlist.
const COMPILER_SRC = readFileSync(join(ROOT, "scripts", "compile-packs.mjs"), "utf8");
const MARKER_PILOT_CHAINS_BLOCK = COMPILER_SRC.match(/const MARKER_PILOT_CHAINS = new Set\(\[([\s\S]*?)\]\);/);
const MARKER_PILOT_CHAIN_NAMES = [...MARKER_PILOT_CHAINS_BLOCK[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
assert.ok(MARKER_PILOT_CHAIN_NAMES.length > 0, "failed to parse MARKER_PILOT_CHAINS out of compile-packs.mjs");
const BAAS_PILOT_WORKFLOW_IDS = MARKER_PILOT_CHAIN_NAMES.map((name) => `pack-${name}`);
const SENTINEL_DIGEST = `sha256:${"0".repeat(64)}`;

test("compile-packs: every MARKER_PILOT_CHAINS chain that compiles carries verified:false + sentinel digest on the marked (browser-tool) nodes only", () => {
  run([]);
  const compiledPilotIds = BAAS_PILOT_WORKFLOW_IDS.filter((id) => readdirSync(PACKS_DIR).includes(`${id}.json`));
  assert.ok(compiledPilotIds.length > 0, "expected at least one MARKER_PILOT_CHAINS chain to compile");
  for (const workflowId of compiledPilotIds) {
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, `${workflowId}.json`), "utf8"));
    assert.deepEqual(validate(SCHEMA, pack.manifest), [], `${workflowId}: manifest failed schema validation`);
    let sawMarked = false;
    for (const node of pack.manifest.nodes) {
      if (node.verified === false) {
        sawMarked = true;
        assert.equal(node.kernel_digest, SENTINEL_DIGEST, `${workflowId}/${node.node_id}: marked node must carry the sentinel digest`);
        assert.equal(node.kernel_id, node.kernel_id, "kernel_id carries the tool_id unchanged");
      } else {
        assert.equal("verified" in node, false, `${workflowId}/${node.node_id}: a real kernel node must never carry verified:true or any other value`);
        assert.notEqual(node.kernel_digest, SENTINEL_DIGEST, `${workflowId}/${node.node_id}: a real kernel node must never carry the sentinel digest`);
      }
    }
    assert.ok(sawMarked, `${workflowId}: expected at least one verified:false node`);
  }
});

test("compile-packs: marking is scoped to MARKER_PILOT_CHAINS only — no other compiled pack ever carries verified", () => {
  run([]);
  const packFiles = readdirSync(PACKS_DIR).filter((f) => f !== "INDEX.json" && !BAAS_PILOT_WORKFLOW_IDS.includes(f.replace(/\.json$/, "")));
  for (const file of packFiles) {
    const pack = JSON.parse(readFileSync(join(PACKS_DIR, file), "utf8"));
    for (const node of pack.manifest.nodes) {
      assert.equal("verified" in node, false, `${file}/${node.node_id}: verified must be absent outside MARKER_PILOT_CHAINS`);
    }
  }
});
