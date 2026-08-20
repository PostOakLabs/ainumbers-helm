// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-WATCH-RECEIPT-1 (HELM-WATCH-BUILD-SPEC.md §1 Q2/Q3, §4 row 3). The
// freshness receipt: a small derived object computed at read time over an
// already-journaled run (never a parallel source of truth), signed the same
// way any other §26.4 object is (bundle.mjs's sealBundleObject — no new
// signing key, no second envelope scheme). This module owns computation +
// sealing + a standalone-verifiable export; it consumes watch-scheduler.mjs's
// watch_runs table and uptime-record.mjs's three-state classifier, and
// invents neither.
import { createHash } from "node:crypto";
import { getWatch, watchBaseline, lastWatchRun, cadenceIntervalMs } from "./watch-scheduler.mjs";
import { isWindowContinuouslyUp, classifyWatchStatus } from "./uptime-record.mjs";
import { sealBundleObject, assembleBundle, browserPublicKeys } from "./bundle.mjs";
import { verifyBundle as verifyBundleOffline, verifyAnchorBinding } from "../ui/lib/verify-bundle.mjs";
import { buildStandaloneVerifierHtml } from "../ui/lib/standalone-verifier.mjs";
import { buildAuditorHtml } from "../ui/lib/auditor-pdf.mjs";
import { buildZip } from "../ui/lib/zip-writer.mjs";

function sha256Hex(s) {
  return createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
}

// The single journal entry (stream `run:${runId}`) this receipt is derived
// from — Q2: "entry_digest copied from that journal entry, not recomputed."
// Takes the LATEST transition for the run (whatever terminal state it
// reached — completed/failed/held), since the receipt reports what was
// observed, not a filtered "only success counts" view.
function latestRunJournalEntry(db, runId) {
  const row = db
    .prepare("SELECT seq, entry_digest, entry_json FROM journal WHERE stream_id = ? ORDER BY seq DESC LIMIT 1")
    .get(`run:${runId}`);
  if (!row) return null;
  const entry = JSON.parse(row.entry_json);
  return { seq: row.seq, digest: `sha256:${row.entry_digest}`, periodEnd: entry.period_end, state: entry.state };
}

// Computes the freshness receipt for one watch as of `nowFn()`. Pure read —
// never writes watches.json, watch_runs, or the journal. Throws if the watch
// is unknown (a receipt over a watch that doesn't exist is a caller error,
// not a "no evidence" observation).
export function computeFreshnessReceipt(db, watchId, { nowFn = () => Date.now() } = {}) {
  const watch = getWatch(watchId);
  if (!watch) throw new Error(`receipt: unknown watch_id "${watchId}"`);

  const nowMs = nowFn();
  const asOf = new Date(nowMs).toISOString();
  const baseline = watchBaseline(db, watchId, watch);
  const baselineMs = Date.parse(baseline);
  const intervalMs = cadenceIntervalMs(watch.cadence);
  const dueBy = new Date(baselineMs + intervalMs).toISOString();
  const due = nowMs >= baselineMs + intervalMs;
  const lastRun = lastWatchRun(db, watchId);

  let journalSeq = null;
  let entryDigest = null;
  let cadenceConformance;
  let status;

  if (!due && lastRun) {
    // The most recent firing's own evidence is still fresh enough to cover
    // "now" — Q3 state 1 (`ran`). expected_by here is the window THIS run
    // satisfied (captured by fireWatch before it advanced the baseline),
    // never the next-due window, so within_window answers "did this run
    // land inside the window it was for" rather than a tautology against
    // its own timestamp.
    const journalEntry = latestRunJournalEntry(db, lastRun.lastRunId);
    status = "ran";
    if (journalEntry) {
      journalSeq = journalEntry.seq;
      entryDigest = journalEntry.digest;
    }
    const ranAt = journalEntry?.periodEnd ?? lastRun.lastFiredAt;
    const expectedBy = lastRun.expectedBy ?? dueBy;
    cadenceConformance = {
      expected_by: expectedBy,
      ran_at: ranAt,
      within_window: Date.parse(ranAt) <= Date.parse(expectedBy),
    };
  } else {
    // No journal entry covers the current window (Q3 states 2/3) — the
    // distinction is phil's partition-safety condition: was helmd itself
    // continuously up for the whole window, or could it simply not have
    // known? uptime-record.mjs's classifier is the single place that draws
    // this line; this row never re-derives it.
    const continuouslyUp = isWindowContinuouslyUp(db, { windowStart: baselineMs, windowEnd: baselineMs + intervalMs });
    status = classifyWatchStatus({ hasJournalEntryInWindow: false, continuouslyUp });
    cadenceConformance = { expected_by: dueBy, ran_at: null, within_window: false };
  }

  // Drift window (this row's binding enhancement, flagged as its fence by
  // HELM-WATCH-UPTIME-1's check-off note): last-observed -> now, explicit
  // duration, computed from watch_runs directly rather than re-derived from
  // the journal — the same "last-observed" instant cadence_conformance's
  // no-run branch already treats as the baseline.
  const lastObservedAt = lastRun?.lastFiredAt ?? watch.created_at;
  const driftWindow = {
    from: lastObservedAt,
    to: asOf,
    duration_ms: nowMs - Date.parse(lastObservedAt),
  };

  return {
    watch_id: watchId,
    journal_seq: journalSeq,
    entry_digest: entryDigest,
    status,
    cadence_conformance: cadenceConformance,
    drift_window: driftWindow,
    ...(watch.evidences !== undefined ? { evidences: watch.evidences } : {}),
    as_of: asOf,
  };
}

// Seals a computed receipt into a §26.4 object — same DSSE/in-toto envelope
// path every other Helm object uses (bundle.mjs's sealBundleObject), no new
// signing key (Q2: "the receipt is signed the same way any other exported
// evidence is signed"). subject binds the receipt to the watch it describes
// via a digest of watch_id (a receipt has no single input file the way a
// `helm check` result does, so this is the closest §26.2-shaped subject).
export function sealFreshnessReceipt(db, watchId, keys, opts) {
  const receipt = computeFreshnessReceipt(db, watchId, opts);
  const sealed = sealBundleObject(
    {
      kind: "freshness_receipt",
      subject: [{ name: "watch_id", digest: { sha256: sha256Hex(watchId) } }],
      predicate: receipt,
    },
    keys
  );
  return { receipt, sealed };
}

// Assembles + verifies + exports a standalone, offline-verifiable bundle for
// one watch's freshness receipt — same shape and same verify chain as
// bundle.mjs's exportRunProofZip, so `helmd verify` (scripts/verify.mjs) and
// the embedded verify.html need zero new code to check a receipt: to them
// this is just another bundle with one sealed object in it.
export async function exportFreshnessReceiptZip(db, watchId, keys, { generatedAt, nowFn } = {}) {
  const { receipt, sealed } = sealFreshnessReceipt(db, watchId, keys, { nowFn });
  const watch = getWatch(watchId);

  const bundle = assembleBundle({
    bundleId: `helm-watch-receipt-${watchId}-${receipt.as_of}`,
    runId: receipt.journal_seq !== null ? watch.watch_id : `watch-${watchId}-no-run`,
    workflowManifestDigest: watch.pack_ref.pack_digest,
    specs: [sealed],
    keys,
  });

  const publicKeys = browserPublicKeys(keys);
  const verifyResult = await verifyBundleOffline(bundle, publicKeys);

  const checkpointsWithBinding = verifyResult.detail.checkpoints.map((cp) => {
    if (!cp.predicate) return cp;
    const anchors = (cp.predicate.anchors ?? []).map((a) => ({ ...a, binding: verifyAnchorBinding(a, cp.predicate.journal_root_digest) }));
    return { ...cp, predicate: { ...cp.predicate, anchors } };
  });

  const verifyHtml = buildStandaloneVerifierHtml({ bundle, publicKeys });
  const auditorHtml = buildAuditorHtml({
    bundle,
    entries: verifyResult.detail.entries,
    checkpoints: checkpointsWithBinding,
    manifestDigest: bundle.manifest.predicate.workflow_manifest_digest,
    generatedAt,
  });
  const readme =
    `Helm freshness receipt — watch "${watchId}"\n\n` +
    `A dated observation, not a promise (SO #0): as of ${receipt.as_of}, status="${receipt.status}".\n\n` +
    `bundle.json   — the raw signed receipt bundle (this IS the evidence)\n` +
    `verify.html   — open this in any browser, fully offline, to re-verify from scratch\n` +
    `auditor.html  — human-readable audit record; print or "print to PDF" for paper records\n\n` +
    `Bundle verified ${verifyResult.valid ? "VALID" : "INVALID"} at export time` +
    (verifyResult.reasons.length ? `: ${verifyResult.reasons.join("; ")}\n` : ".\n");

  return {
    receipt,
    valid: verifyResult.valid,
    reasons: verifyResult.reasons,
    zip: buildZip([
      { name: "bundle.json", data: JSON.stringify(bundle, null, 2) },
      { name: "verify.html", data: verifyHtml },
      { name: "auditor.html", data: auditorHtml },
      { name: "README.txt", data: readme },
    ]),
  };
}
