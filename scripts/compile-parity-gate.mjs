#!/usr/bin/env node
// Compile parity gate (HELM-P2-C2, HELM-PHASE2-BUILD-SPEC.md §2/§8 row C2/§10 gate 1).
//
// Proves compiling a chain into a pack manifest (C1) preserves execution semantics: for
// every compiled pack, this runs its nodes through helmd's REAL execution path (hub/run.mjs
// executeRun() + hub/kernel-runner.mjs runKernelNode() — the same code the daemon uses for a
// live run) and asserts each node's artifact.execution_hash equals the CANONICAL reference —
// kernel.buildArtifact() invoked directly against the vendored kernel registry with the same
// input. The canonical call stands in for "the site/browser run of the same kernels" per D3
// (kernel files are pinned byte-identical browser<->hub, verified independently by
// verify-vendored.mjs) — so a helmd/canonical match here proves the compile step's node
// extraction (kernel_id + kernel_digest pin, argument order) introduces no divergence, not
// just that two calls to the same function agree.
//
// Compiled manifests carry no policy_parameters (real inputs arrive at run time from
// declared_inputs) — this fixture injects each node's OWN kernel fixture vector so both paths
// run on identical, real input rather than a synthetic stub.
import { readFileSync, readdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { KERNELS } from "../hub/vendored/ocg/kernels/index.mjs";
import { runKernelNode } from "../hub/kernel-runner.mjs";
import { executeRun } from "../hub/run.mjs";
import { openJournal } from "../hub/journal.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const PACKS_DIR = join(ROOT, "packs");
const FIXTURES_DIR = join(ROOT, "hub", "vendored", "ocg", "kernels", "fixtures");
const NOW = "2026-01-01T00:00:00.000Z";
const STRICT = process.argv.includes("--strict");

function sampleInputFor(kernelId) {
  const fpath = join(FIXTURES_DIR, `${kernelId}.fixtures.json`);
  const doc = JSON.parse(readFileSync(fpath, "utf8"));
  const vector = doc.vectors?.[0];
  if (!vector) throw new Error(`compile-parity-gate: ${kernelId} has a fixtures file but no vectors — cannot sample an input`);
  return vector.policy_parameters;
}

function stable(x) {
  if (Array.isArray(x)) return x.map(stable);
  if (x && typeof x === "object") {
    return Object.keys(x).sort().reduce((o, k) => { o[k] = stable(x[k]); return o; }, {});
  }
  return x;
}
const sameShape = (a, b) => JSON.stringify(stable(a)) === JSON.stringify(stable(b));

export async function runParityGate({ packsDir = PACKS_DIR, db } = {}) {
  const packFiles = readdirSync(packsDir).filter((f) => f !== "INDEX.json");
  if (packFiles.length === 0) {
    throw new Error(`compile-parity-gate: ${packsDir} is empty — run \`npm run packs:compile\` first`);
  }

  let checkedPacks = 0, checkedNodes = 0, matched = 0, diverged = 0, hardErrors = 0;
  const divergences = [];

  for (const file of packFiles) {
    const pack = JSON.parse(readFileSync(join(packsDir, file), "utf8"));
    checkedPacks++;

    const manifest = {
      ...pack.manifest,
      nodes: pack.manifest.nodes.map((n) => ({ ...n, policy_parameters: sampleInputFor(n.kernel_id) })),
    };

    const helmdArtifacts = new Map(); // step_id -> artifact, captured as the daemon's real stepRunner is invoked
    let helmdResult;
    try {
      helmdResult = await executeRun(db, {
        runId: `parity-${pack.workflow_id}`,
        manifest,
        stepRunner: async (step) => {
          const result = await runKernelNode(step, { now: NOW });
          helmdArtifacts.set(step.step_id, result);
          return result;
        },
      });
    } catch (e) {
      console.error(`✗ ${pack.workflow_id}: helmd run threw — ${e.message}`);
      hardErrors++;
      continue;
    }
    if (helmdResult.state !== "completed") {
      console.error(`✗ ${pack.workflow_id}: helmd run ended in state "${helmdResult.state}", expected "completed"`);
      hardErrors++;
      continue;
    }

    for (const node of manifest.nodes) {
      checkedNodes++;
      const stepId = `nodes:${node.node_id}`;
      const helmdSide = helmdArtifacts.get(stepId);
      if (!helmdSide) {
        console.error(`✗ ${pack.workflow_id}/${node.node_id}: no helmd-side artifact captured (memoized without re-running?)`);
        hardErrors++;
        continue;
      }

      // Canonical reference: the vendored kernel invoked directly, with the exact
      // defaults runKernelNode uses for a fresh (no chain-history) node — the
      // "browser/site" run per D3 kernel-file parity.
      const kernel = KERNELS[node.kernel_id];
      const canonicalArtifact = await kernel.buildArtifact(node.policy_parameters, {
        now: NOW,
        parent_hashes: [],
        parent_tool_ids: [],
        chain_depth: 0,
      });

      const outputsMatch = sameShape(helmdSide.artifact.output_payload, canonicalArtifact.output_payload);
      const hashesMatch = helmdSide.artifact.execution_hash === canonicalArtifact.execution_hash;

      if (outputsMatch && hashesMatch) {
        matched++;
      } else {
        diverged++;
        const entry = {
          workflow_id: pack.workflow_id,
          node_id: node.node_id,
          kernel_id: node.kernel_id,
          helmd_hash: helmdSide.artifact.execution_hash,
          canonical_hash: canonicalArtifact.execution_hash,
          outputs_match: outputsMatch,
          hashes_match: hashesMatch,
        };
        divergences.push(entry);
        console.error(
          `✗ ${pack.workflow_id}/${node.node_id} (${node.kernel_id}): PARITY DIVERGENCE\n` +
          `    outputs_match=${outputsMatch} hashes_match=${hashesMatch}\n` +
          `    helmd_hash     ${helmdSide.artifact.execution_hash}\n` +
          `    canonical_hash ${canonicalArtifact.execution_hash}`
        );
      }
    }
  }

  return { checkedPacks, checkedNodes, matched, diverged, hardErrors, divergences };
}

async function main() {
  const tmpDir = mkdtempSync(join(tmpdir(), "helm-compile-parity-"));
  const db = openJournal(join(tmpDir, "parity.db"));
  let result;
  try {
    result = await runParityGate({ db });
  } finally {
    db.close();
    rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log(
    `\ncompile-parity: ${result.matched}/${result.checkedNodes} node(s) byte-identical across ` +
    `${result.checkedPacks} pack(s) (${result.diverged} divergence(s), ${result.hardErrors} hard error(s)).`
  );

  if (result.hardErrors > 0) {
    console.error(`\n✗ ${result.hardErrors} hard error(s) — always CI-blocking.`);
    process.exit(1);
  }
  if (result.diverged > 0) {
    console.error(`\n${STRICT ? "✗" : "⚠"} ${result.diverged} node(s) diverge between helmd and the canonical kernel run.`);
    process.exit(1); // no known-divergence allowlist exists (or is expected) for this gate — always CI-blocking
  }
  console.log("✓ compile-parity-gate clean.");
  process.exit(0);
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
