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

export function pairingUrl(token, port) {
  return `http://127.0.0.1:${port}/#token=${token}`;
}

export function tokenMatches(token, presented) {
  if (typeof presented !== "string" || presented.length === 0) return false;
  const a = Buffer.from(token, "utf8");
  const b = Buffer.from(presented, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
