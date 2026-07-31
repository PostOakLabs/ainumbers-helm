// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-ANCHOR-RETRY-1 (G1, research/HELM-RELAY-STUB-1-2026-07-27.md §5): before
// this module, anchorForCheckpoint recorded a schema-valid `status:"queued"`
// marker on relay failure (anchor-client.mjs) but nothing ever drained it — a
// transient relay blip permanently un-anchored that checkpoint. Measured:
// `grep -rni "drain\|re-anchor\|reanchor\|retryAnchor" --include=*.mjs hub/ bin/`
// returned exactly one unrelated hit (bin/helmd.mjs:98, process-exit code)
// before this row.
//
// This module owns retry bookkeeping ONLY — persisting queued markers to disk
// and re-attempting the RFC 3161 call for them. It never touches a checkpoint:
// a checkpoint's anchors[] is inside its signed envelope (checkpoint.mjs
// buildCheckpoint), so an already-signed checkpoint can never be rewritten.
// A resolved retry is returned to the caller; wiring it into a FUTURE
// checkpoint's anchors[] is a separate concern, out of this row's fence.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { log } from "./log.mjs";

const QUEUE_FILE = "anchor-queue.json";

// anchor.ainumbers.co's RELAY_LIMITER caps at 4 requests/min/IP
// (anchor-suite/src/worker.mjs:1337-1342, memorialized in
// HELM-RELAY-STUB-1-2026-07-27.md §5 G2 and this row's own contract). Spacing
// retries at 20s keeps a single helmd instance's drain pass to 3 req/min,
// leaving headroom in the same bucket for the checkpoint-anchoring call that
// triggers a drain pass (anchor-client.mjs) and any concurrent MCP
// anchor_hash traffic sharing the same NAT'd IP (G2).
export const MIN_RETRY_INTERVAL_MS = 20_000;

function queuePath() {
  return statePath(QUEUE_FILE);
}

export function loadAnchorQueue() {
  const path = queuePath();
  if (!existsSync(path)) return [];
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    // A hand-edited or corrupted queue file must never crash a checkpoint
    // attempt — treat it as empty and let the next successful save repair it.
    return [];
  }
}

function saveAnchorQueue(entries) {
  writeFileSync(queuePath(), JSON.stringify(entries, null, 2) + "\n", { mode: 0o600 });
}

// Persists a queue marker so a later drain pass can find it. ⛔ status:"skipped"
// (egress_blocked — the operator's zero-egress choice, or offline:true) is
// NEVER enqueued: retrying a marker the operator explicitly chose not to
// anchor would make anchoring a silent standing dependency, which is the
// specific thing phil's non-negotiable (this row's contract) forbids.
export function enqueueAnchorRetry(marker) {
  if (!marker || marker.status !== "queued" || !marker.journal_root_digest) return;
  const entries = loadAnchorQueue().filter((e) => e.checkpoint_seq !== marker.checkpoint_seq);
  entries.push({ ...marker });
  saveAnchorQueue(entries);
}

function resolveAnchorRetry(checkpointSeq) {
  saveAnchorQueue(loadAnchorQueue().filter((e) => e.checkpoint_seq !== checkpointSeq));
}

function requeueAnchorRetry(entry, { reason, attempts, lastAttemptAt, buildQueueMarker }) {
  const updated = buildQueueMarker({
    checkpointSeq: entry.checkpoint_seq,
    status: "queued",
    reason,
    relayUrl: entry.relay_url,
    attempts,
    lastAttemptAt,
    journalRootDigest: entry.journal_root_digest,
    now: () => lastAttemptAt,
  });
  const remaining = loadAnchorQueue().filter((e) => e.checkpoint_seq !== entry.checkpoint_seq);
  remaining.push(updated);
  saveAnchorQueue(remaining);
}

// Retries every queued entry that has a digest to re-stamp, oldest-enqueued
// first. Sequential, never concurrent — one relay call in flight at a time —
// and spaced at `minIntervalMs` (see MIN_RETRY_INTERVAL_MS) so a drain pass
// can be invoked as often as a caller likes without ever exceeding the
// relay's rate limit. An entry retried more recently than `minIntervalMs` ago
// is skipped THIS pass (not retried anyway, not dropped) — it will be picked
// up on a later pass once its own cooldown clears. `anchorRfc3161Impl` is
// injected (default the real anchor-client.mjs function) purely to avoid a
// circular import; `buildQueueMarkerImpl` likewise.
export async function drainAnchorQueue({
  ca = "freetsa",
  relayBase,
  fetchImpl = fetch,
  minIntervalMs = MIN_RETRY_INTERVAL_MS,
  now = () => Date.now(),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  anchorRfc3161Impl,
  buildQueueMarkerImpl,
} = {}) {
  const resolved = [];
  const entries = loadAnchorQueue();
  let lastAttemptClock = 0;

  for (const entry of entries) {
    if (!entry.journal_root_digest) continue; // nothing to re-stamp without a digest

    const lastAttemptMs = entry.last_attempt_at ? Date.parse(entry.last_attempt_at) : 0;
    if (now() - lastAttemptMs < minIntervalMs) continue; // this entry's own cooldown hasn't cleared

    if (lastAttemptClock > 0) {
      const elapsed = now() - lastAttemptClock;
      if (elapsed < minIntervalMs) await sleep(minIntervalMs - elapsed);
    }
    lastAttemptClock = now();

    const digest = entry.journal_root_digest.replace(/^sha256:/, "");
    const attemptedAt = new Date(now()).toISOString();
    try {
      const anchor = await anchorRfc3161Impl(digest, { ca, relayBase, fetchImpl });
      resolveAnchorRetry(entry.checkpoint_seq);
      resolved.push({ checkpointSeq: entry.checkpoint_seq, anchor });
      log.info("anchor queue: retry succeeded", { checkpointSeq: entry.checkpoint_seq });
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("unknown relay CA")) throw err; // caller bug, not a retry condition
      const reason = err instanceof Error && err.message.startsWith("anchor relay") ? "relay_error" : "relay_unreachable";
      requeueAnchorRetry(entry, {
        reason,
        attempts: (entry.attempts ?? 0) + 1,
        lastAttemptAt: attemptedAt,
        buildQueueMarker: buildQueueMarkerImpl,
      });
      log.warn("anchor queue: retry failed, staying queued", {
        checkpointSeq: entry.checkpoint_seq,
        attempts: (entry.attempts ?? 0) + 1,
        reason,
      });
    }
  }
  return resolved;
}
