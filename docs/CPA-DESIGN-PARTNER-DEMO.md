# CPA design-partner demo pack: one-pager + synthetic-data runbook

Docs only. No code in this repo changed to produce this file.

⚠ **Everything in this document and in the accompanying fixture
(`helm/fixtures/cpa-demo-substantive-procedure-cycle.synthetic.json`) is synthetic.**
No real client, no real firm, no real engagement, no real balance appears anywhere
below. Substitute your own extract before running this against a real client
population.

---

## Part 1: the one-page framing sheet (hand this to the firm)

**What this pack is.** `pack-substantive-procedure-cycle` runs four deterministic
kernels back to back against data you supply:

| Node | Kernel | What it recomputes |
|---|---|---|
| n1 | `art-462-je-ruleset-screen` | Journal-entry rule screen: weekend/holiday postings, round numbers, suspense-account postings, post-close postings, unauthorized user/account pairs |
| n2 | `art-463-recalc-suite` | Recalculation suite: depreciation, interest accrual, EPS, amortization, prepaid roll-forwards, each against a stated tolerance |
| n3 | `art-464-confirmation-matcher` | Bank/AR confirmation-to-ledger matching, five-way classification (exact / within-tolerance / mismatch / no-ledger / no-confirmation) |
| n4 | `art-465-workpaper-bundle-composer` | Assembles the three kernels' outputs, an exception list with recorded dispositions, and preparer/reviewer/partner role statements into one evidence bundle |

Each kernel's execution is a pinned, deterministic recomputation: same inputs
always produce the same `execution_hash`, and every hop is content-addressed
back to the kernel's own vendored digest (`hub/kernel-runner.mjs`, D2 invariant).
That is what "re-runnable, offline-verifiable" means in practice. A second
person, on a different machine, months later, can re-run the same inputs
through the same pinned kernels and get the identical hash, or can hand the
exported bundle to `verify.html` and check it with **no daemon, no network
call, no vendor dependency**.

**What this pack is *not*.** It is not a general ledger, not an ERP connector,
not a materiality or going-concern judgment tool, and it does not decide
sampling or scope. The pack's own manifest says so explicitly ("Estimates,
going concern, and materiality stay out of scope by design; these kernels are
recalculation, rule screens, and matching only"). Partner release inside the
pack is single-signer and is always recorded as `review_required` under the
OCG §27 Human Accountability vocabulary. Runtime dual-control gating (a
second required approver before release) is not yet wired in Phase 1.

**AU-C 500 framing: what this pack does, not what it proves.** AU-C 500
describes the auditor's responsibility to obtain sufficient appropriate audit
evidence. This pack's role in that picture is narrow: it gives you a
deterministic, hash-verifiable *recomputation* of specific procedures
(recalculation, a rule-based screen, and a confirmation match), the same kind
of evidence AU-C 500 already recognizes as recomputation and reperformance,
just produced with a machine-checkable audit trail instead of a spreadsheet
you can't independently re-derive later. **It does not, on its own, satisfy an
auditor's evidence obligations for an area or an engagement.** The auditor's
professional judgment, about sufficiency, appropriateness, scope, sampling,
and materiality, sits entirely outside this pack, exactly where AU-C 500
puts it. Treat every artifact this pack produces as one input to that
judgment, never as a substitute for it.

**No assurance promise, no SLA.** This one-pager describes what the software
does today. It makes no promise about update cadence, support response time,
or future kernel coverage; see Helm's own `docs/OPERATIONS.md` for what is
and isn't operationally guaranteed.

---

## Part 2: synthetic-data runbook, run the pack end to end

This walks through running `packs/pack-substantive-procedure-cycle.json`
against the synthetic fixture in this repo and reading the resulting
`evidence_bundle_manifest` (schema: `schema/evidence_bundle_manifest.schema.json`,
normative shape: SPEC.md §26.7).

### 0. Prerequisites

- A checkout of this repo (`ainumbers-helm`, branch `main`).
- Node.js 22.5 or newer (`package.json` `engines.node`). No `npm install`
  needed for this walkthrough; it only imports modules already in the repo.
- Nothing else. This runbook never starts `helmd`, never opens a network
  connection, and never touches a real connector. The pack's own manifest
  declares zero connectors (`declared_inputs: []`), so every input below is
  supplied directly as `policy_parameters`.

⚠ `loadOrCreateKeys()` (`hub/keys.mjs`, step 2 below) creates or reuses the
same local, OS-keychain-protected signing key `helmd` itself uses for every
bundle it signs on this machine. It is not a demo-only throwaway key. That
is expected: it is the same call `hub/check.mjs` makes for a real `helm
check` run. No key material or state ever leaves the local machine.

### 1. The synthetic fixture

`helm/fixtures/cpa-demo-substantive-procedure-cycle.synthetic.json` carries
one block of `policy_parameters` per kernel (`n1_je_ruleset_screen`,
`n2_recalc_suite`, `n3_confirmation_matcher`, `n4_workpaper_bundle_composer_roles`),
shaped to match each kernel's own fixture vectors
(`hub/vendored/ocg/kernels/fixtures/art-46{2,3,4,5}-*.fixtures.json`, the
golden-parity fixtures those kernels ship with). Every id, name, and balance in
it is invented for this demo.

To run this against your own synthetic (never real) data, copy the file and
edit the four blocks. The field names are exactly what each kernel's own
fixture vectors use, so cross-check against those files if a kernel rejects
your input.

### 2. Run the pack, no daemon required

Today's Phase 1 build ships two no-daemon entry points: `helmd run-template
<slug>` (for the handful of scenarios bundled as demo templates,
`hub/templates.mjs`) and `helmd check <pack_id> <input_file>` (for the one
pack currently registered in `hub/check.mjs`'s `CHECK_ADAPTERS`). Neither is
wired to `pack-substantive-procedure-cycle` yet, so this runbook shows the
same underlying path both of those use: `hub/run.mjs`'s `executeRun()` plus
`hub/bundle.mjs`'s `assembleBundle()`, as a short script. This mirrors
`scripts/run-template.mjs` and `hub/check.mjs` line for line; nothing here is
new machinery.

Save the following as a scratch file (e.g. `run-cpa-demo.mjs`) **outside this
repo's tracked tree** and run it with `node run-cpa-demo.mjs` from the
`helm/` directory:

```js
// Illustrative only. Not a committed repo script. Run from the helm/
// directory: node run-cpa-demo.mjs
import { readFileSync } from "node:fs";
import { getPack } from "./hub/packs.mjs";
import { openJournal } from "./hub/journal.mjs";
import { executeRun } from "./hub/run.mjs";
import { createKernelStepRunner } from "./hub/kernel-runner.mjs";
import { sealBundleObject, assembleBundle } from "./hub/bundle.mjs";
import { loadOrCreateKeys } from "./hub/keys.mjs";

const fixture = JSON.parse(
  readFileSync("./fixtures/cpa-demo-substantive-procedure-cycle.synthetic.json", "utf8")
);

const pack = getPack("pack-substantive-procedure-cycle");
if (!pack) throw new Error("pack not found in this build's compiled pack catalog: run `npm run packs:compile` in a full checkout first");

// Clone the manifest and wire the synthetic policy_parameters into n1-n3.
// n4 (the composer) needs n1-n3's execution hashes, so it's built after they run.
const manifest = structuredClone(pack.manifest);
const byNode = Object.fromEntries(manifest.nodes.map((n) => [n.node_id, n]));
byNode.n1.policy_parameters = fixture.n1_je_ruleset_screen;
byNode.n2.policy_parameters = fixture.n2_recalc_suite;
byNode.n3.policy_parameters = fixture.n3_confirmation_matcher;

const db = openJournal(":memory:"); // in-memory journal for this walkthrough only
const stepRunner = createKernelStepRunner();
const runId = "cpa-demo-run-1";

// First pass: run n1-n3 only (drop n4) so we can read their execution hashes.
const firstPass = structuredClone(manifest);
firstPass.nodes = firstPass.nodes.filter((n) => n.node_id !== "n4");
const firstResult = await executeRun(db, { runId, manifest: firstPass, stepRunner });
console.log("n1-n3 state:", firstResult.state, "execution_hash:", firstResult.executionHash);

// Pull each kernel's printed execution_hash from its artifact's audit_signature
// (inspect the printed step output once: the exact field path is stable
// within a kernel version but this script deliberately reads it live rather
// than hardcoding it).
const kernelArtifacts = [];
for (const nodeId of ["n1", "n2", "n3"]) {
  const row = db
    .prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?")
    .get(runId, `nodes:${nodeId}`);
  const output = JSON.parse(row.output_json);
  kernelArtifacts.push({
    tool_id: output.kernel_id,
    execution_hash: output.artifact.audit_signature.execution_hash,
  });
}

// Second run: full manifest (n1-n4), n4 now wired with the real hashes.
byNode.n4.policy_parameters = {
  ...fixture.n4_workpaper_bundle_composer_roles,
  kernel_artifacts: kernelArtifacts,
};
const fullResult = await executeRun(db, { runId: "cpa-demo-run-2", manifest, stepRunner });
console.log("full run state:", fullResult.state, "execution_hash:", fullResult.executionHash);

// Seal each step's output as a bundle object and assemble the evidence_bundle_manifest.
const keys = loadOrCreateKeys(); // see loadOrCreateKeys() for where these live
const sealed = [];
for (const nodeId of ["n1", "n2", "n3", "n4"]) {
  const row = db
    .prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?")
    .get("cpa-demo-run-2", `nodes:${nodeId}`);
  const output = JSON.parse(row.output_json);
  sealed.push(
    sealBundleObject(
      {
        kind: "step_result",
        subject: [{ name: nodeId, digest: { sha256: output.kernel_digest.replace(/^sha256:/, "") } }],
        predicate: output,
      },
      keys
    )
  );
}

const bundle = assembleBundle({
  bundleId: "cpa-demo-bundle-1",
  runId: "cpa-demo-run-2",
  workflowManifestDigest: pack.workflow_manifest_digest,
  specs: sealed,
  keys,
});

console.log(JSON.stringify(bundle.manifest.predicate, null, 2));
db.close();
```

### 3. Reading the `evidence_bundle_manifest`

The script's last line prints `bundle.manifest.predicate`, an object
matching `schema/evidence_bundle_manifest.schema.json`:

| Field | What it means here |
|---|---|
| `bundle_id` | Your chosen label for this bundle (`cpa-demo-bundle-1` above). |
| `run_id` | The run this bundle covers (`cpa-demo-run-2`). |
| `workflow_manifest_digest` | The pack's own manifest digest. Matches `pack-substantive-procedure-cycle.json`'s `workflow_manifest_digest` field, so a reviewer can confirm which pack version produced this bundle without re-running anything. |
| `entries[]` | One entry per sealed object, here one per kernel node (n1 through n4). Each carries `kind` (`step_result`), `digest` (the sealed envelope's own hash), and `trust_label`. Every entry in this walkthrough is `kernel_verified`, §26.6's label for "reproducing the recorded deterministic kernel from recorded inputs is itself the proof." |
| `checkpoints_ref[]` | Empty in this minimal walkthrough (no journal checkpoint was taken). A `helmd`-run engagement normally anchors a checkpoint here; see `hub/checkpoint.mjs`. |
| `redaction_profile` | `default-v1`, the default redaction backstop (`hub/bundle.mjs`'s `assertRedacted`) already refused to seal anything carrying a field named like a secret or raw payload. This label records that the export ran under that backstop. |

To go from the printed manifest to a shareable, self-verifying file, pass the
same `bundle` object to `exportBundleZip()` (`hub/bundle.mjs`). It writes
`bundle.json` (the manifest above), `verify.html` (opens in any browser,
fully offline, no daemon), and `auditor.html` (a human-readable, printable
record). That is the artifact you would actually hand to a design-partner
firm; see item 4 of the demo-pack contents in `CPA-RAILS-BUILD-SPEC.md` §5.

### 4. What a real engagement changes

Everything above ran against invented data. For a real pilot engagement:

- Replace every value in the fixture with the firm's own synthetic test data
  first, and only move to real data once the firm's own engagement team has
  reviewed the pack's scope and limitations against Part 1 above.
- Real data never belongs in this repo, in `helm/fixtures/`, or in any commit.
  Helm runs entirely on the firm's own machine; nothing here changes that
  (per `CPA-RAILS-BUILD-SPEC.md` §5 item 1, extending the same zero-PII
  posture the rest of this estate follows).
- The `review_required` single-signer partner release noted in Part 1 is a
  Phase 1 limitation, not a design endorsement. Treat runtime dual control as
  a manual process step until it's wired.
