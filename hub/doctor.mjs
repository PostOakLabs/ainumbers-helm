// Self-check: config readable, token file mode 0600, state dir private, port free.
import { statSync, existsSync, readFileSync } from "node:fs";
import { platform } from "node:os";
import { createServer } from "node:net";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { stateDir, statePath } from "./state-dir.mjs";
import { loadConfig } from "./config.mjs";
import { loadOrCreateToken } from "./token.mjs";
import { openJournal, replayVerify } from "./journal.mjs";
import { checkVersion } from "./version-check.mjs";
import { uiAssetsReadable } from "./static.mjs";

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

  const portFree = await checkPortFree(config.port);
  checks.push({ name: "port_available", pass: portFree, detail: config.port });

  // HELM-U4: helmd serves the UI itself now — a doctor that passes but can't
  // actually read ui/helm.html (missing SEA asset, moved dev checkout) would
  // still hand back a green report for a daemon that 404s its own homepage.
  checks.push({ name: "ui_assets_readable", pass: uiAssetsReadable() });

  // D6 replay-journal-on-restart integrity check: recompute every stream's
  // running hash from scratch and compare to what's stored. A missing
  // journal.db is not a failure (fresh install, nothing to replay yet).
  const journalPath = statePath("journal.db");
  if (existsSync(journalPath)) {
    const db = openJournal(journalPath);
    const replay = replayVerify(db);
    checks.push({ name: "journal_replay_integrity", pass: replay.ok, detail: replay.ok ? undefined : JSON.stringify(replay.brokenAt) });
    db.close();
  } else {
    checks.push({ name: "journal_replay_integrity", pass: true, detail: "no journal.db yet" });
  }

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
