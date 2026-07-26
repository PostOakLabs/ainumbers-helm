// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Single config file: ~/.helm/config.json. Created with defaults on first run.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { statePath } from "./state-dir.mjs";
import { DEFAULT_IDLE_TIMEOUT_MS } from "./idle-timer.mjs";
import { RELAY_CA_LIST } from "./anchor-client.mjs";

const DEFAULT_PORT = 4173;
// HELM-ANCHOR-DEFAULT-FLIP-1: same relay/CA anchor-client.mjs falls back to
// when a caller passes nothing — repeated here (not imported) so a config
// with no anchor fields set still round-trips to the exact values a caller
// omitting relayBase/ca would already get, making these fields genuinely
// optional rather than a silent behavior change the first time they're read.
const DEFAULT_RELAY_BASE = "https://anchor.ainumbers.co";
const DEFAULT_CA = "freetsa";
// D10: passive notice only, never an auto-updater. Empty string disables
// the check entirely (airgapped installs).
const DEFAULT_VERSION_CHECK_URL = "https://ainumbers.co/helm/version.json";

// helmd serves the UI itself (HELM-U4, Syncthing pattern) — the page's real
// Origin is http://127.0.0.1:<port>, so that's what gets exact-matched
// (never a wildcard) per D8. Derived from `port`, not hardcoded, so a
// port-only override in config.json still gets a correct default.
function defaultOrigin(port) {
  return `http://127.0.0.1:${port}`;
}

export function loadConfig() {
  const path = statePath("config.json");
  if (!existsSync(path)) {
    const config = {
      port: DEFAULT_PORT,
      allowedOrigin: defaultOrigin(DEFAULT_PORT),
      versionCheckUrl: DEFAULT_VERSION_CHECK_URL,
      // §18.3: written out explicitly (not left implicit) so the file itself
      // is where a user retunes it, per Tim's "we can always change it".
      idleTimeoutMs: DEFAULT_IDLE_TIMEOUT_MS,
    };
    writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
    return {
      ...config,
      anchorRequired: false,
      anchorOnCheckpoint: false,
      relayBase: DEFAULT_RELAY_BASE,
      ca: DEFAULT_CA,
      path,
    };
  }
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const port = parsed.port ?? DEFAULT_PORT;
  if (parsed.ca !== undefined && !RELAY_CA_LIST.includes(parsed.ca)) {
    throw new Error(`config.json: "ca" must be one of ${RELAY_CA_LIST.join(", ")}, got "${parsed.ca}"`);
  }
  return {
    port,
    allowedOrigin: parsed.allowedOrigin ?? defaultOrigin(port),
    versionCheckUrl: parsed.versionCheckUrl ?? DEFAULT_VERSION_CHECK_URL,
    idleTimeoutMs: parsed.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
    // HELM-UX-1 §9.4: when true, the journal-checkpoint boot fast path only
    // trusts an ANCHORED checkpoint — an unanchored one falls back to a full
    // replay, same as an invalid one. Still defaults off: anchoring itself
    // (below) can legitimately land as a queued/skipped marker (offline,
    // relay down), and that's still a valid checkpoint — requiring a REAL
    // anchor for the fast path is a stricter, separate opt-in.
    anchorRequired: parsed.anchorRequired ?? false,
    // HELM-ANCHOR-WIRE-1: opt-OUT, not opt-in. Anchoring a fresh checkpoint
    // is a network call (anchor-client.mjs → anchor.ainumbers.co), but it is
    // provably non-blocking (runs after the daemon is already listening) and
    // never fails a checkpoint (an unreachable/blocked relay just yields a
    // schema-valid queued/skipped marker, per §5 exit-gate #1) — there is no
    // safety reason to make every install discover and flip a flag before
    // the examiner-facing trust chain this row exists for actually works.
    // HELM-ANCHOR-DEFAULT-FLIP-1: flipped to opt-IN. Two public claims
    // (repo/trust/network-behavior.html, repo/helm.html) say no request
    // leaves the machine without the operator asking for it — true only if
    // the daemon's own default never dials out. Set to `true` in
    // ~/.helm/config.json to opt in to anchoring on checkpoint.
    anchorOnCheckpoint: parsed.anchorOnCheckpoint ?? false,
    // HELM-ANCHOR-DEFAULT-FLIP-1: operator-settable so a distrustful install
    // can point directly at its own choice of TSA (or a private relay) and
    // remove Post Oak Labs' relay from the path entirely — these were
    // already threaded through anchor-client.mjs's anchorForCheckpoint(),
    // this just exposes them. Default relay/CA unchanged.
    relayBase: parsed.relayBase ?? DEFAULT_RELAY_BASE,
    ca: parsed.ca ?? DEFAULT_CA,
    path,
  };
}
