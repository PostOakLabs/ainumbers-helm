// Anchor client (D6/§26.5): submits checkpoint digests to external timestamp
// authorities and returns `anchors[]` members — {type, ...} with
// type ∈ rfc3161 | opentimestamps (scitt-receipt is reserved, never emitted).
//
// RFC 3161 path reuses the SHIPPED Anchor Suite relay (anchor.ainumbers.co)
// and its vendored TimeStampReq builder (hub/vendored/anchor-suite/lib/tsq.mjs,
// same code anchor.html/verify.html run in-browser) — never reimplement the
// DER encoding here.
//
// OpenTimestamps path talks directly to a public OTS calendar over the
// documented calendar submission protocol (POST the raw digest, get back a
// serialized partial Timestamp attesting "this digest existed at this time,
// pending Bitcoin confirmation"). Phase 1 stores that pending attestation
// as-is; upgrading it to a full Merkle-to-block-header proof (the async
// step full OTS clients do later) is out of scope here — see D12.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { buildTsqDer, freshNonce } from "./vendored/anchor-suite/lib/tsq.mjs";
import { extractMessageImprintHex } from "./vendored/ocg/kernels/_rfc3161.mjs";
import { validate } from "../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ANCHOR_QUEUE_MARKER_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "schema", "anchor_queue_marker.schema.json"), "utf8")
);

const RELAY_BASE = "https://anchor.ainumbers.co";
const RELAY_CAS = ["digicert", "sectigo", "freetsa"];
const OTS_CALENDARS = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://alice.btc.calendar.opentimestamps.org",
];

function hexToBytes(hex) {
  const clean = hex.replace(/^sha256:/, "");
  return new Uint8Array(Buffer.from(clean, "hex"));
}

// hashHex: lowercase sha256 hex digest of the object being anchored (e.g. a
// checkpoint's journal_root_digest). ca: one of RELAY_CAS, default "freetsa".
export async function anchorRfc3161(hashHex, { ca = "freetsa", relayBase = RELAY_BASE, timeoutMs = 35_000, fetchImpl = fetch } = {}) {
  if (!RELAY_CAS.includes(ca)) throw new Error(`unknown relay CA "${ca}"`);
  const nonce = freshNonce();
  const tsqDer = buildTsqDer(hexToBytes(hashHex), nonce);

  const res = await fetchImpl(`${relayBase}/relay/${ca}`, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: tsqDer,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`anchor relay HTTP ${res.status} (${ca})`);
  const ct = (res.headers.get("Content-Type") || "").split(";")[0].trim();
  if (ct !== "application/timestamp-reply") throw new Error(`anchor relay unexpected Content-Type: ${ct}`);
  const der = Buffer.from(await res.arrayBuffer());

  // F11: a relay could return a token bound to a DIFFERENT digest than the
  // one we asked it to stamp (bug, MITM, or a malicious relay). Assert the
  // structural binding immediately, at anchor time, rather than trusting the
  // stored DER until some later verify pass happens to check it.
  const returnedImprint = extractMessageImprintHex(der.toString("base64"));
  if (returnedImprint !== hashHex) {
    throw new Error(`anchor relay ${ca} returned a token bound to a different digest (messageImprint ${returnedImprint} != requested ${hashHex})`);
  }

  return {
    type: "rfc3161",
    ca,
    log_origin: `${relayBase}/relay/${ca}`,
    anchored_hash: `sha256:${hashHex}`,
    der: der.toString("base64"),
    requested_at: new Date().toISOString(),
  };
}

// Submits the raw digest to a public OTS calendar. Returns the calendar's
// pending-attestation response verbatim (base64) plus the digest it attests —
// NOT a fully serialized .ots file (no DetachedTimestampFile header/op-tree
// wrapping) and NOT yet upgraded to a Bitcoin block proof.
export async function anchorOpenTimestamps(hashHex, { calendar = OTS_CALENDARS[0], timeoutMs = 20_000 } = {}) {
  const digest = hexToBytes(hashHex);
  const res = await fetch(`${calendar}/digest`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/vnd.opentimestamps.v1" },
    body: digest,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`OTS calendar HTTP ${res.status} (${calendar})`);
  const pending = Buffer.from(await res.arrayBuffer());

  return {
    type: "opentimestamps",
    calendar,
    anchored_hash: `sha256:${hashHex}`,
    pending_proof: pending.toString("base64"),
    upgraded: false,
    submitted_at: new Date().toISOString(),
  };
}

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// checkpointSeq/journalRootDigest tie the marker back to the checkpoint it
// stands in for, per schema/anchor_queue_marker.schema.json. Throws if the
// built marker isn't schema-valid — a bug here must never produce a silently
// malformed marker.
export function buildQueueMarker({ checkpointSeq, status, reason, relayUrl, attempts = 0, lastAttemptAt, journalRootDigest, now = () => new Date().toISOString() }) {
  const marker = {
    checkpoint_seq: checkpointSeq,
    status,
    reason,
    relay_url: relayUrl,
    recorded_at: now(),
    attempts,
  };
  if (lastAttemptAt) marker.last_attempt_at = lastAttemptAt;
  if (journalRootDigest) marker.journal_root_digest = journalRootDigest.startsWith("sha256:") ? journalRootDigest : `sha256:${journalRootDigest}`;
  const errs = validate(ANCHOR_QUEUE_MARKER_SCHEMA, marker);
  if (errs.length) throw new Error(`anchor-client: built an invalid queue marker — ${errs.join("; ")}`);
  return marker;
}

// R15-F5: the orchestrating caller anchorRfc3161()/anchorOpenTimestamps() never
// had — try/catch around the relay call, classifying failure into the schema's
// three reasons, and NEVER letting a relay failure abort checkpoint creation.
// A relay failure (or offline:true, zero-egress) returns { queueMarker }
// instead of throwing; hashHex: the checkpoint's journal_root_digest (bare hex
// or "sha256:"-prefixed).
export async function anchorForCheckpoint(hashHex, { checkpointSeq, ca = "freetsa", relayBase = RELAY_BASE, timeoutMs = 35_000, offline = false, fetchImpl = fetch } = {}) {
  const clean = hashHex.replace(/^sha256:/, "").toLowerCase();
  const relayUrl = `${relayBase}/relay/${ca}`;

  if (offline) {
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "skipped",
        reason: "egress_blocked",
        relayUrl,
        attempts: 0,
        journalRootDigest: clean,
      }),
    };
  }

  const attemptedAt = new Date().toISOString();
  try {
    const anchor = await anchorRfc3161(clean, { ca, relayBase, timeoutMs, fetchImpl });
    return { anchor };
  } catch (err) {
    // anchorRfc3161 throws "anchor relay ..." Errors AFTER it has a response
    // in hand (bad status, bad content-type, or a mismatched messageImprint —
    // see F11 above) — those are relay_error. Anything else (fetch itself
    // throwing: DNS failure, ECONNREFUSED, AbortSignal timeout) never got a
    // response at all — relay_unreachable. An unknown-CA error is a caller
    // bug, not a relay condition, and is left to throw rather than queued.
    if (err instanceof Error && err.message.startsWith("unknown relay CA")) throw err;
    const reason = err instanceof Error && err.message.startsWith("anchor relay") ? "relay_error" : "relay_unreachable";
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "queued",
        reason,
        relayUrl,
        attempts: 1,
        lastAttemptAt: attemptedAt,
        journalRootDigest: clean,
      }),
    };
  }
}

// Projects an anchorForCheckpoint() result into the shape checkpoint.mjs's
// buildCheckpoint() puts in a checkpoint predicate's anchors[] — a real
// anchor as-is, or (per schema/checkpoint.schema.json's widened anchor def,
// HELM-P3-SEC-3) a trimmed queue-marker view keyed by type=queued|skipped.
// checkpoint_seq/journal_root_digest are dropped here since they're redundant
// inside a checkpoint that already carries both at its own predicate root.
export function toCheckpointAnchorEntry({ anchor, queueMarker }) {
  if (anchor) return anchor;
  const { status, reason, relay_url, recorded_at, attempts, last_attempt_at } = queueMarker;
  const entry = { type: status, reason, relay_url: relay_url, recorded_at, attempts };
  if (last_attempt_at) entry.last_attempt_at = last_attempt_at;
  return entry;
}

export const ANCHOR_QUEUE_MARKER_SCHEMA_REF = ANCHOR_QUEUE_MARKER_SCHEMA;
export const RELAY_CA_LIST = RELAY_CAS;
export const OTS_CALENDAR_LIST = OTS_CALENDARS;
