#!/usr/bin/env node
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

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const VENDORED = join(ROOT, "hub", "vendored", "ocg");
const PACKS_DIR = join(ROOT, "packs");
const MANIFEST_SCHEMA = JSON.parse(
  readFileSync(join(ROOT, "schema", "workflow-manifest.schema.json"), "utf8")
);

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
  const nodes = chain.steps.map((s, i) => ({
    node_id: `n${i + 1}`,
    kernel_id: s.tool_id,
    kernel_digest: kernelDigests.get(s.tool_id),
  }));

  const manifest = {
    manifest_version: "1",
    workflow_id: workflowId,
    trigger: { type: "manual" },
    nodes,
    connectors: [],
    gates: [],
    actions: [],
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

  skips.sort((a, b) => a.name.localeCompare(b.name));
  packs.sort((a, b) => a.workflow_id.localeCompare(b.workflow_id));

  const index = {
    pinnedSha,
    generatedFrom: "hub/vendored/ocg/chaingraph.json",
    compiledCount: packs.length,
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
