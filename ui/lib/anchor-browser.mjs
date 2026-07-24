// Browser-mode anchor client (HELM-P3-A5; HELM-PHASE3-BUILD-SPEC.md §1 P3-D4).
//
// Browser-direct RFC 3161 is CORS-dead — no public TSA sends
// Access-Control-Allow-Origin, so a page on ainumbers.co cannot submit a
// TimeStampReq straight to a TSA. The shipped anchor relay Worker
// (anchor.ainumbers.co, same code the daemon's hub/anchor-client.mjs talks
// to) is the ONLY browser-mode anchor path. The relay is untrusted: it
// forwards bytes, but this module verifies the returned TimeStampToken's
// messageImprint against the hash WE asked for before ever calling it an
// "anchor" — a relay that returns a token bound to a different hash (or
// garbage) is rejected exactly like a network failure, not silently
// accepted.
//
// Traffic shape (§2 "boring traffic" rule): one plain HTTPS POST, DER
// request / DER response, no websockets/SSE, no cert pinning (TLS-
// intercepting corporate proxies re-sign everything — pinning would just
// break inside a bank).
//
// Zero-egress copy (P3-D4 "itemize the hash-only flow"): the ONLY network
// call this module ever makes is POST https://anchor.ainumbers.co/relay/<ca>
// with the SHA-256 hash of the checkpoint's journal_root_digest — never
// journal contents, never any entry payload. Callers that must guarantee no
// egress at all (zero-egress export) pass { offline: true }, which skips
// the fetch entirely and records why (schema/anchor_queue_marker.schema.json).
import { buildTsqDer, freshNonce, hexToBytes, bytesToBase64 } from "../vendored/der-encode.mjs";
import { parseRfc3161MessageImprint } from "../vendored/der.mjs";
import { validate } from "../vendored/schema-validator.mjs";
import ANCHOR_QUEUE_MARKER_SCHEMA from "../vendored/schemas/anchor_queue_marker.schema.mjs";

export const RELAY_BASE = "https://anchor.ainumbers.co";
export const RELAY_CAS = ["digicert", "sectigo", "freetsa"];

function relayUrlFor(relayBase, ca) {
  return `${relayBase}/relay/${ca}`;
}

// checkpointSeq/journalRootDigest identify the marker's checkpoint per the
// schema (both required to tie a marker back without re-parsing the
// checkpoint). status/reason per the schema enums.
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
  if (errs.length) throw new Error(`anchor-browser: built an invalid queue marker — ${errs.join("; ")}`);
  return marker;
}

// hashHex: lowercase sha256 hex digest (bare or "sha256:"-prefixed) of the
// checkpoint's journal_root_digest. Returns { anchor } on a verified success
// or { queueMarker } on anything else (relay unreachable, non-2xx, bad
// content type, or a returned token that does NOT bind to hashHex) — the
// caller never has to distinguish "network down" from "relay lied," both
// are untrusted-until-verified and both queue.
export async function submitAnchor(
  hashHex,
  {
    checkpointSeq,
    ca = "freetsa",
    relayBase = RELAY_BASE,
    timeoutMs = 35_000,
    fetchImpl = fetch,
    offline = false,
  } = {}
) {
  const clean = hashHex.replace(/^sha256:/, "").toLowerCase();
  const relayUrl = relayUrlFor(relayBase, ca);
  const attemptedAt = new Date().toISOString();

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

  if (!RELAY_CAS.includes(ca)) throw new Error(`unknown relay CA "${ca}"`);

  let res;
  try {
    const nonce = freshNonce();
    const tsqDer = buildTsqDer(hexToBytes(clean), nonce);
    res = await fetchImpl(relayUrl, {
      method: "POST",
      headers: { "Content-Type": "application/timestamp-query" },
      body: tsqDer,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    // Network failure, timeout, or DNS/TLS error — relay simply wasn't reachable.
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "queued",
        reason: "relay_unreachable",
        relayUrl,
        attempts: 1,
        lastAttemptAt: attemptedAt,
        journalRootDigest: clean,
      }),
    };
  }

  if (!res.ok) {
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "queued",
        reason: "relay_error",
        relayUrl,
        attempts: 1,
        lastAttemptAt: attemptedAt,
        journalRootDigest: clean,
      }),
    };
  }
  const ct = (res.headers.get("Content-Type") || "").split(";")[0].trim();
  if (ct !== "application/timestamp-reply") {
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "queued",
        reason: "relay_error",
        relayUrl,
        attempts: 1,
        lastAttemptAt: attemptedAt,
        journalRootDigest: clean,
      }),
    };
  }

  const derBytes = new Uint8Array(await res.arrayBuffer());
  const derB64 = bytesToBase64(derBytes);

  // Client-side verification against our OWN hash (P3-D4: "Client verifies
  // the returned TST against its own hash — the relay stays untrusted"). A
  // structurally malformed response or one bound to a different hash than
  // we asked for is treated exactly like the relay never answered.
  let parsed;
  try {
    parsed = parseRfc3161MessageImprint(derB64);
  } catch {
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "queued",
        reason: "relay_error",
        relayUrl,
        attempts: 1,
        lastAttemptAt: attemptedAt,
        journalRootDigest: clean,
      }),
    };
  }
  if (parsed.hashedMessageHex !== clean) {
    return {
      queueMarker: buildQueueMarker({
        checkpointSeq,
        status: "queued",
        reason: "relay_error",
        relayUrl,
        attempts: 1,
        lastAttemptAt: attemptedAt,
        journalRootDigest: clean,
      }),
    };
  }

  return {
    anchor: {
      type: "rfc3161",
      ca,
      log_origin: relayUrl,
      anchored_hash: `sha256:${clean}`,
      der: derB64,
      requested_at: attemptedAt,
      genTime: parsed.genTime,
      policyOid: parsed.policyOid,
    },
  };
}

export const ANCHOR_QUEUE_MARKER_SCHEMA_REF = ANCHOR_QUEUE_MARKER_SCHEMA;
