// Bearer-token pairing: random token in a mode-0600 file, one-time #token= URL
// printed by the CLI on start. Every HTTP call must carry it (D8).
import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { statePath } from "./state-dir.mjs";

export function loadOrCreateToken() {
  const path = statePath("token");
  if (existsSync(path)) {
    chmodSync(path, 0o600);
    return readFileSync(path, "utf8").trim();
  }
  const token = randomBytes(32).toString("hex");
  writeFileSync(path, token, { mode: 0o600 });
  chmodSync(path, 0o600);
  return token;
}

// pair= carries a nonce, separate from the durable bearer token: P3-D9
// requires the pairing LINK itself be single-use and short-TTL even though
// the bearer token it delivers stays durable for the session (revoking it
// on every call would break EventSource/health polling, which can't rotate
// credentials mid-connection). The nonce's only power is /pair/redeem
// (records the pairing event, so a replayed old link is detectable) — it
// never gates ordinary API calls, matching "unlocks daemon APIs ONLY."
//
// fp= carries the daemon identity-key fingerprint (R15-F1 fix): the ONLY
// channel a port squatter cannot spoof, because only real helmd — the
// process holding ~/.helm/keys.enc.json — ever mints this URL. The browser
// pins it and later refuses to trust ANY /pair/challenge response whose
// publicKey fingerprint doesn't match, closing the self-consistency-only
// gap in challenge.mjs's verifyChallenge.
export function pairingUrl(token, port, pairNonce, fingerprint) {
  const pair = pairNonce ? `&pair=${pairNonce}` : "";
  const fp = fingerprint ? `&fp=${fingerprint}` : "";
  return `http://127.0.0.1:${port}/#token=${token}${pair}${fp}`;
}

export function tokenMatches(token, presented) {
  if (typeof presented !== "string" || presented.length === 0) return false;
  const a = Buffer.from(token, "utf8");
  const b = Buffer.from(presented, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// In-memory only (module-level Map, cleared on daemon restart — deliberate:
// pairing nonces are ephemeral loopback artifacts, never worth persisting).
const PAIRING_TTL_MS = 5 * 60 * 1000;
const pairingNonces = new Map(); // nonce -> expiresAtMs

export function createPairingNonce(now = Date.now()) {
  const nonce = randomBytes(16).toString("hex");
  pairingNonces.set(nonce, now + PAIRING_TTL_MS);
  return nonce;
}

// Single-use by construction: the nonce is deleted whether or not it was
// still valid, so a second redeem of the same value always fails, matching
// P3-D9 even for a link that was accidentally reused before it expired.
export function redeemPairingNonce(nonce, now = Date.now()) {
  const expiresAt = pairingNonces.get(nonce);
  pairingNonces.delete(nonce);
  if (!expiresAt) return false;
  return now <= expiresAt;
}
