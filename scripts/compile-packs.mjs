#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Pack compiler (HELM-P2-C1, HELM-PHASE2-BUILD-SPEC.md §2): compiles the site
// repo's ~300 named chains (vendored, pinned copy of chaingraph.json) into
// §26.3-conformant workflow-pack manifests. Vendoring-pattern generator —
// same single-writer discipline as vendor.mjs / mcp-apps-poc/generate.mjs.
// CANNOT run in any cloud build: local generator only, packs/ committed in
// the SAME push as a vendor.mjs re-vendor.
//
// Triage (DEC-4 LOCKED — accept a compiled SUBSET, never block on 100%): a
// chain compiles ONLY if every step's tool_id resolves to a kernel that is
// BOTH gpu:false in the pinned chaingraph AND actually vendored into
// hub/vendored/ocg/kernels (the same registry kernel-runner.mjs enforces at
// run time — a pack that compiles here is guaranteed runnable there). Any
// other chain (browser widget, composer, non-kernel node, or gpu:true /
// not-yet-vendored kernel) is SKIPPED with a logged reason — never silently
// dropped (ABSENCE-INSTRUMENT rule).
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { cgCanon, assertIJson } from "../hub/vendored/ocg/kernels/_hash.mjs";
import { validate } from "./lib/schema-validator.mjs";
import { loadContract } from "../hub/connector.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const VENDORED = join(ROOT, "hub", "vendored", "ocg");
const PACKS_DIR = join(ROOT, "packs");
const MANIFEST_SCHEMA = JSON.parse(
  readFileSync(join(ROOT, "schema", "workflow-manifest.schema.json"), "utf8")
);
// HELM-HA-1 §1 item 5 (OPTIONAL): a curated overlay of §27.4 gate_policy
// onto specific compiled nodes, applied every run since packs/ is wiped +
// regenerated wholesale below — see ha-gate-overlay.json's own comment for
// why this lives here instead of in site chaingraph.json (out of fence) or
// a hand-authored pack file (would be deleted on the next compile).
const HA_GATE_OVERLAY = JSON.parse(
  readFileSync(join(HERE, "ha-gate-overlay.json"), "utf8")
).packs;
// BANK-NYDFS-HPACK-1 (HELM-HA-BUILD-SPEC.md §3.6): curated chainless packs —
// same "survives the wholesale wipe+regen" pattern as HA_GATE_OVERLAY above,
// for packs with no source chain at all (see chainless-packs.json's own
// comment for why a hand-placed packs/*.json file doesn't work here).
// HELM-BIND-4 (HELM-DATA-BINDING-BUILD-SPEC.md §5): curated overlay naming
// the packs whose kernel has no other way to get a real input value than an
// external fetch — same "survives the wholesale wipe+regen" pattern as
// HA_GATE_OVERLAY/CHAINLESS_PACKS above. `_comment` is a human note, not a
// workflow_id, and is skipped everywhere this object is iterated.
const CONNECTOR_BINDINGS = JSON.parse(
  readFileSync(join(HERE, "connector-bindings.json"), "utf8")
);

const CHAINLESS_PACKS = JSON.parse(
  readFileSync(join(HERE, "chainless-packs.json"), "utf8")
).packs;

function jcsDigestHex(obj) {
  assertIJson(obj);
  return createHash("sha256").update(JSON.stringify(cgCanon(obj))).digest("hex");
}

function sha256ref(hex) {
  return `sha256:${hex}`;
}

// Same lookup kernel-runner.mjs uses at run time (vendored/ocg/MANIFEST.json,
// keyed by the kernel file's own sha256) — a pack this compiler emits pins
// EXACTLY the digest the runner will later re-verify against, so compile-time
// and run-time can never silently drift apart.
function loadKernelDigests() {
  const manifest = JSON.parse(readFileSync(join(VENDORED, "MANIFEST.json"), "utf8"));
  const map = new Map();
  for (const f of manifest.files) {
    if (f.path.startsWith("kernels/") && f.path.endsWith(".kernel.mjs")) {
      map.set(f.path.slice("kernels/".length, -".kernel.mjs".length), sha256ref(f.sha256));
    }
  }
  return { map, pinnedSha: manifest.pinnedSha };
}

// Best-effort declared-input derivation (first cut, DEC-4 spirit): only the
// chain's entry step can have inputs the user must actually supply — every
// later step's inputs are kernel-internal wiring, bound to the prior step's
// output by the chain's own handoff order.
function declaredInputsFor(chain, nodesById) {
  const first = chain.steps[0];
  const node = nodesById.get(first.tool_id);
  return (node?.consumes ?? []).map((upstream) => ({ from: upstream, kind: "external" }));
}

function compileChain(chain, kernelDigests, nodesById) {
  const missing = chain.steps.filter((s) => !kernelDigests.has(s.tool_id)).map((s) => s.tool_id);
  if (missing.length > 0) {
    return { skip: { name: chain.name, reason: `non-kernel or unvendored step(s): ${missing.join(", ")}` } };
  }

  const workflowId = `pack-${chain.name}`;
  const gateOverlay = HA_GATE_OVERLAY[workflowId] ?? {};
  const nodes = chain.steps.map((s, i) => {
    const nodeId = `n${i + 1}`;
    return { node_id: nodeId, kernel_id: s.tool_id, kernel_digest: kernelDigests.get(s.tool_id), ...(gateOverlay[nodeId] ?? {}) };
  });

  // HELM-BIND-4: a workflow_id present in CONNECTOR_BINDINGS gets a real
  // connector + connector_inputs + required_inputs wiring; every other pack
  // keeps connectors:[] and both optional members ABSENT (§0.3 — an absent
  // key does not enter the JCS canonical form, an empty array does).
  const binding = CONNECTOR_BINDINGS[workflowId];
  const manifest = {
    manifest_version: "1",
    workflow_id: workflowId,
    trigger: { type: "manual" },
    nodes,
    connectors: binding
      ? [{
          connector_id: binding.connector_id,
          contract_digest: loadContract(join(ROOT, "hub", "connectors", binding.contract_file)).contractDigest,
        }]
      : [],
    gates: [],
    actions: [],
    ...(binding
      ? {
          connector_inputs: [{
            step_id: `bind-${binding.feeds_node_id}-${binding.feeds_param}`,
            connector_id: binding.connector_id,
            feeds_node_id: binding.feeds_node_id,
            feeds_param: binding.feeds_param,
          }],
          required_inputs: [binding.required_input],
        }
      : {}),
  };

  const errs = validate(MANIFEST_SCHEMA, manifest);
  if (errs.length > 0) {
    throw new Error(`compile-packs: chain "${chain.name}" produced a non-conformant manifest:\n  ${errs.join("\n  ")}`);
  }

  const pack = {
    workflow_id: workflowId,
    name: chain.title ?? chain.name,
    outcome: chain.description ?? "",
    spec_version: "ocg-control-plane@1",
    manifest,
    workflow_manifest_digest: sha256ref(jcsDigestHex(manifest)),
    declared_inputs: declaredInputsFor(chain, nodesById),
    // Every compiled node is a pure decision kernel by construction (that IS
    // the compile-eligibility test above) — "compute" is an honest default,
    // not a guess; a future WU can refine per-node once nodes carry a
    // reliable classification field (today semantic_profile is present on
    // <5% of nodes, too sparse to drive Run-view badges).
    steps_meta: nodes.map((n) => ({ node_id: n.node_id, data_classification: "compute" })),
  };

  return { pack };
}

// BANK-NYDFS-HPACK-1: a curated chainless-packs.json entry is already a
// full, schema-conformant manifest (attested_artifacts pinned digests +
// gated nodes) — this just validates it and derives the same
// workflow_manifest_digest/steps_meta shape a chain-compiled pack gets, so
// nothing downstream (packs.mjs, getPack, /run/start) can tell the two
// sources apart.
function compileChainlessEntry(entry) {
  const { workflow_id: workflowId, name, outcome, manifest } = entry;
  const errs = validate(MANIFEST_SCHEMA, manifest);
  if (errs.length > 0) {
    throw new Error(`compile-packs: chainless-packs.json entry "${workflowId}" produced a non-conformant manifest:\n  ${errs.join("\n  ")}`);
  }
  return {
    workflow_id: workflowId,
    name,
    outcome,
    spec_version: "ocg-control-plane@1",
    manifest,
    workflow_manifest_digest: sha256ref(jcsDigestHex(manifest)),
    declared_inputs: [],
    steps_meta: (manifest.nodes ?? []).map((n) => ({ node_id: n.node_id, data_classification: "compute" })),
  };
}

function loadChaingraph() {
  const g = JSON.parse(readFileSync(join(VENDORED, "chaingraph.json"), "utf8"));
  const nodesById = new Map(g.nodes.map((n) => [n.tool_id, n]));
  return { chains: g.chains, nodesById };
}

function generate() {
  const { map: kernelDigests, pinnedSha } = loadKernelDigests();
  const { chains, nodesById } = loadChaingraph();

  const packs = [];
  const skips = [];
  for (const chain of chains) {
    const result = compileChain(chain, kernelDigests, nodesById);
    if (result.skip) skips.push(result.skip);
    else packs.push(result.pack);
  }

  // BANK-NYDFS-HPACK-1: merge in curated chainless packs before the overlay
  // sanity checks below, so a chainless workflow_id is eligible for
  // HA_GATE_OVERLAY too (not used today — chainless-packs.json's own nodes
  // already carry gate_policy inline — but keeps one merge point, not two).
  const chainCount = packs.length;
  for (const entry of CHAINLESS_PACKS) {
    if (packs.some((p) => p.workflow_id === entry.workflow_id)) {
      throw new Error(`compile-packs: chainless-packs.json workflow_id "${entry.workflow_id}" collides with a chain-compiled pack`);
    }
    packs.push(compileChainlessEntry(entry));
  }
  const chainlessCount = packs.length - chainCount;

  skips.sort((a, b) => a.name.localeCompare(b.name));
  packs.sort((a, b) => a.workflow_id.localeCompare(b.workflow_id));

  // ABSENCE-INSTRUMENT: an overlay entry naming a workflow_id/node_id that
  // never actually compiled (typo, renamed chain, gpu:true skip) would
  // silently stop applying — fail loudly instead of shipping a "gated" pack
  // that quietly isn't.
  const compiledNodeIds = new Map(packs.map((p) => [p.workflow_id, new Set(p.manifest.nodes.map((n) => n.node_id))]));
  for (const [workflowId, nodeOverlays] of Object.entries(HA_GATE_OVERLAY)) {
    const nodeIds = compiledNodeIds.get(workflowId);
    if (!nodeIds) throw new Error(`compile-packs: ha-gate-overlay.json names workflow_id "${workflowId}" which did not compile — stale/typo'd overlay entry`);
    for (const nodeId of Object.keys(nodeOverlays)) {
      if (!nodeIds.has(nodeId)) throw new Error(`compile-packs: ha-gate-overlay.json names node "${nodeId}" in "${workflowId}" which doesn't exist in the compiled manifest`);
    }
  }

  // Same ABSENCE-INSTRUMENT check for HELM-BIND-4's connector-bindings.json —
  // a stale/typo'd entry must fail loudly, not silently stop wiring a real
  // connector into what looks (from the pack alone) like an unbound pack.
  for (const [workflowId, binding] of Object.entries(CONNECTOR_BINDINGS)) {
    if (workflowId === "_comment") continue;
    const nodeIds = compiledNodeIds.get(workflowId);
    if (!nodeIds) throw new Error(`compile-packs: connector-bindings.json names workflow_id "${workflowId}" which did not compile — stale/typo'd overlay entry`);
    if (!nodeIds.has(binding.feeds_node_id)) throw new Error(`compile-packs: connector-bindings.json names node "${binding.feeds_node_id}" in "${workflowId}" which doesn't exist in the compiled manifest`);
  }

  const index = {
    pinnedSha,
    generatedFrom: "hub/vendored/ocg/chaingraph.json",
    compiledCount: packs.length,
    chainlessCount,
    skippedCount: skips.length,
    skips,
  };

  return { packs, index };
}

function writeOut({ packs, index }) {
  rmSync(PACKS_DIR, { recursive: true, force: true });
  mkdirSync(PACKS_DIR, { recursive: true });
  for (const pack of packs) {
    writeFileSync(join(PACKS_DIR, `${pack.workflow_id}.json`), JSON.stringify(pack, null, 2) + "\n");
  }
  writeFileSync(join(PACKS_DIR, "INDEX.json"), JSON.stringify(index, null, 2) + "\n");
}

function readExisting() {
  if (!existsSync(PACKS_DIR)) return null;
  const out = {};
  for (const name of readdirSync(PACKS_DIR)) {
    out[name] = readFileSync(join(PACKS_DIR, name), "utf8");
  }
  return out;
}

function checkFresh({ packs, index }) {
  const existing = readExisting();
  if (!existing) {
    console.error(`compile-packs --check: ${PACKS_DIR} does not exist — run \`node scripts/compile-packs.mjs\` first`);
    return false;
  }

  const expected = {};
  for (const pack of packs) expected[`${pack.workflow_id}.json`] = JSON.stringify(pack, null, 2) + "\n";
  expected["INDEX.json"] = JSON.stringify(index, null, 2) + "\n";

  const expectedNames = new Set(Object.keys(expected));
  const existingNames = new Set(Object.keys(existing));
  let ok = true;

  for (const name of expectedNames) {
    if (!existingNames.has(name)) {
      console.error(`compile-packs --check: missing ${name} (stale packs/ vs pinned ${index.pinnedSha})`);
      ok = false;
    } else if (existing[name] !== expected[name]) {
      console.error(`compile-packs --check: ${name} is stale vs pinned ${index.pinnedSha} — re-run \`node scripts/compile-packs.mjs\``);
      ok = false;
    }
  }
  for (const name of existingNames) {
    if (!expectedNames.has(name)) {
      console.error(`compile-packs --check: ${name} on disk but no longer produced by the compiler — stale, remove or re-run`);
      ok = false;
    }
  }
  return ok;
}

const checkMode = process.argv.includes("--check");
const result = generate();

if (checkMode) {
  const fresh = checkFresh(result);
  if (!fresh) process.exit(1);
  console.log(`compile-packs --check: fresh — ${result.packs.length} compiled, ${result.index.skippedCount} skipped, pinned ${result.index.pinnedSha}`);
  process.exit(0);
}

writeOut(result);
console.log(
  `compile-packs: wrote ${result.packs.length} pack(s) + INDEX.json to packs/ (pinned ${result.index.pinnedSha}); ${result.index.skippedCount} chain(s) skipped (see INDEX.json)`
);
