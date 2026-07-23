#!/usr/bin/env node
// helmd — local-first control plane hub daemon. Loopback REST+SSE (D8
// hardened) + named-pipe/UDS CLI channel + doctor self-check.
import { loadConfig } from "./config.mjs";
import { loadOrCreateToken, pairingUrl } from "./token.mjs";
import { createHelmServer } from "./server.mjs";
import { createCliChannel } from "./cli-channel.mjs";
import { runDoctor } from "./doctor.mjs";
import { log } from "./log.mjs";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { platform } from "node:os";
import { statePath } from "./state-dir.mjs";
import { openJournal, replayVerify } from "./journal.mjs";

// No "open" package (zero-dep, D2) — shell out to each OS's native opener.
// Best-effort: a failure here (headless box, no default browser configured)
// is a warning, never fatal — the printed pairing URL is always the fallback.
function openBrowser(url) {
  try {
    const plat = platform();
    if (plat === "win32") execFileSync("cmd", ["/c", "start", "", url], { stdio: "ignore" });
    else if (plat === "darwin") execFileSync("open", [url], { stdio: "ignore" });
    else execFileSync("xdg-open", [url], { stdio: "ignore" });
  } catch (err) {
    log.warn("could not auto-open browser", { error: String(err?.message || err) });
  }
}

async function cmdDoctor() {
  const report = await runDoctor();
  for (const c of report.checks) {
    console.log(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail !== undefined ? `  (${c.detail})` : ""}`);
  }
  process.exit(report.ok ? 0 : 1);
}

function cmdStart({ open = false } = {}) {
  const config = loadConfig();
  const isFirstRun = !existsSync(statePath("token"));
  const token = loadOrCreateToken();

  // D6: replay-journal-on-restart integrity check. A daemon must never come
  // up serving a journal it can't prove is unbroken.
  const journalPath = statePath("journal.db");
  if (existsSync(journalPath)) {
    const db = openJournal(journalPath);
    const replay = replayVerify(db);
    db.close();
    if (!replay.ok) {
      log.error("journal replay integrity check FAILED — refusing to start", { brokenAt: replay.brokenAt });
      process.exit(1);
    }
    log.info("journal replay integrity check passed");
  }

  createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token });
  createCliChannel({
    health: () => ({ status: "ok" }),
  });

  log.info("helmd started", { port: config.port });
  const url = pairingUrl(token, config.port);
  console.log(url);

  // First-run zero-CLI-copy-paste onboarding (HELM-U4): the pairing link
  // opens itself. `--open` forces the same behavior on any later start
  // (e.g. a future `helm open` wrapper shelling out to `helmd start --open`).
  if (isFirstRun || open) openBrowser(url);
}

const args = process.argv.slice(2);
const cmd = args[0] || "start";
if (cmd === "doctor") await cmdDoctor();
else if (cmd === "start") cmdStart({ open: args.includes("--open") });
else {
  console.error(`helmd: unknown command "${cmd}" (expected: start | doctor)`);
  process.exit(1);
}
