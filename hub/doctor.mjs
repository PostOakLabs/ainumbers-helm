// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Self-check: config readable, token file mode 0600, state dir private, and
// the configured port either free or held by our own helmd.
import { statSync, existsSync, readFileSync } from "node:fs";
import { platform } from "node:os";
import { createServer } from "node:net";
import { request as httpRequest } from "node:http";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { stateDir, statePath } from "./state-dir.mjs";
import { loadConfig } from "./config.mjs";
import { loadOrCreateToken } from "./token.mjs";
import { openJournal, replayVerify, recordFullVerification, lastFullVerifiedAt } from "./journal.mjs";
import { checkVersion } from "./version-check.mjs";
import { uiAssetsReadable } from "./static.mjs";
import { autostartDoctorCheck } from "./autostart.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CURRENT_VERSION = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8")).version;

function checkPortFree(port) {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.once("error", () => resolve(false));
    probe.once("listening", () => probe.close(() => resolve(true)));
    probe.listen(port, "127.0.0.1");
  });
}

// Asks whoever holds the port to identify itself. /version is the
// unauthenticated detection route (server.mjs handleDetectionRoute), so this
// needs no bearer token; it answers only for the loopback UI origin or the
// hosted one, so we send the configured allowedOrigin. A non-helmd listener
// returns something else, or nothing, and we report the port as occupied.
function probeDaemonVersion(port, allowedOrigin) {
  return new Promise((resolve) => {
    const req = httpRequest(
      { host: "127.0.0.1", port, path: "/version", method: "GET", headers: { Origin: allowedOrigin }, timeout: 2000 },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(body);
            resolve(res.statusCode === 200 && typeof parsed.daemon === "string" ? parsed.daemon : null);
          } catch {
            resolve(null);
          }
        });
      }
    );
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
}

// An unbindable port used to be an automatic FAIL, which meant `helmd doctor`
// failed BY DESIGN on a healthy system: the running daemon is what holds the
// port, and INSTALL.md points users at doctor as the post-install check. So
// the documented first thing a new user does reported FAIL and implied the
// port was squatted. Distinguish the three real cases instead.
async function checkPort(port, allowedOrigin) {
  if (await checkPortFree(port)) return { pass: true, detail: `${port} free (helmd not running)` };
  const version = await probeDaemonVersion(port, allowedOrigin);
  if (version) return { pass: true, detail: `${port} in use by helmd ${version}` };
  return { pass: false, detail: `${port} in use by another process` };
}

export async function runDoctor() {
  const checks = [];

  checks.push({ name: "state_dir_exists", pass: existsSync(stateDir()) });

  const config = loadConfig();
  checks.push({ name: "config_readable", pass: !!config.port });

  const token = loadOrCreateToken();
  const tokenPath = statePath("token");
  const mode = statSync(tokenPath).mode & 0o777;
  const tokenModeOk = platform() === "win32" ? true : mode === 0o600;
  checks.push({ name: "token_file_mode_0600", pass: tokenModeOk, detail: mode.toString(8) });
  checks.push({ name: "token_present", pass: token.length > 0 });

  const port = await checkPort(config.port, config.allowedOrigin);
  checks.push({ name: "port_ok", pass: port.pass, detail: port.detail });

  // HELM-U4: helmd serves the UI itself now — a doctor that passes but can't
  // actually read ui/helm.html (missing SEA asset, moved dev checkout) would
  // still hand back a green report for a daemon that 404s its own homepage.
  checks.push({ name: "ui_assets_readable", pass: uiAssetsReadable() });

  // D6/§9.1 full replay-from-genesis integrity check: recompute every
  // stream's running hash from scratch and compare to what's stored. Boot
  // itself no longer does this unconditionally (it verifies from the last
  // checkpoint forward instead, see index.mjs) — doctor is now the place
  // "prove the whole history" actually happens, and §9.4 wants the result
  // of the last time that ran surfaced, not just implied by a clean boot.
  // A missing journal.db is not a failure (fresh install, nothing to replay
  // yet).
  const journalPath = statePath("journal.db");
  if (existsSync(journalPath)) {
    const db = openJournal(journalPath);
    const replay = replayVerify(db);
    if (replay.ok) recordFullVerification(db);
    checks.push({
      name: "journal_replay_integrity",
      pass: replay.ok,
      detail: replay.ok ? `last full verification: ${lastFullVerifiedAt(db)}` : JSON.stringify(replay.brokenAt),
    });
    db.close();
  } else {
    checks.push({ name: "journal_replay_integrity", pass: true, detail: "no journal.db yet" });
  }

  // HELM-ANCHOR-DEFAULT-FLIP-1: anchoring is opt-in (default off) — this is
  // informational, same as version_check_notice below, never a FAIL: an
  // unanchored checkpoint is a fully valid, supported configuration, not a
  // broken one. Its whole job is making sure an operator who never re-runs
  // doctor after first setup still has ONE place that says so, per §20/the
  // examiner-facing trust chain — the boot-log warn (index.mjs) is the other.
  checks.push({
    name: "anchor_on_checkpoint",
    pass: true,
    detail: config.anchorOnCheckpoint
      ? `checkpoints anchored via ${config.relayBase}/relay/${config.ca}`
      : `checkpoints NOT anchored (opt-in) — set "anchorOnCheckpoint": true in ~/.helm/config.json to enable`,
  });

  // HELM-AUTOSTART-1 §4: autostart is opt-in and default-off, so "not
  // enabled" is a PASS. What is NOT a pass is an entry that exists and can no
  // longer do its job — `isInstalled` only ever checked that the registry
  // value / plist existed, never that the path baked into it still resolves,
  // so a user who moved or re-downloaded the binary had a Run key that failed
  // silently at every logon while every status surface said healthy.
  checks.push(autostartDoctorCheck());

  // Version-check notice (HELM-H8, D10): informational only. Unreachable
  // (offline/airgapped) or disabled (empty url) are both a PASS — this
  // never gates doctor on network access. A reachable-but-malformed
  // response is the one failure worth surfacing (server misconfigured).
  if (config.versionCheckUrl) {
    const versionCheck = await checkVersion({ currentVersion: CURRENT_VERSION, url: config.versionCheckUrl });
    const malformed = !versionCheck.checked && versionCheck.errs;
    checks.push({
      name: "version_check_notice",
      pass: !malformed,
      detail: versionCheck.checked
        ? (versionCheck.upToDate ? "up to date" : `update available: ${versionCheck.latestVersion}`)
        : versionCheck.reason,
    });
  } else {
    checks.push({ name: "version_check_notice", pass: true, detail: "disabled" });
  }

  const allPass = checks.every((c) => c.pass);
  return { ok: allPass, checks };
}
