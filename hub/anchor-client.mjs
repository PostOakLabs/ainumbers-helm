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
import { buildTsqDer, freshNonce } from "./vendored/anchor-suite/lib/tsq.mjs";

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
export async function anchorRfc3161(hashHex, { ca = "freetsa", relayBase = RELAY_BASE, timeoutMs = 35_000 } = {}) {
  if (!RELAY_CAS.includes(ca)) throw new Error(`unknown relay CA "${ca}"`);
  const nonce = freshNonce();
  const tsqDer = buildTsqDer(hexToBytes(hashHex), nonce);

  const res = await fetch(`${relayBase}/relay/${ca}`, {
    method: "POST",
    headers: { "Content-Type": "application/timestamp-query" },
    body: tsqDer,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`anchor relay HTTP ${res.status} (${ca})`);
  const ct = (res.headers.get("Content-Type") || "").split(";")[0].trim();
  if (ct !== "application/timestamp-reply") throw new Error(`anchor relay unexpected Content-Type: ${ct}`);
  const der = Buffer.from(await res.arrayBuffer());

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

export const RELAY_CA_LIST = RELAY_CAS;
export const OTS_CALENDAR_LIST = OTS_CALENDARS;
