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
import { statePath } from "./state-dir.mjs";
import { openJournal, replayVerify } from "./journal.mjs";

async function cmdDoctor() {
  const report = await runDoctor();
  for (const c of report.checks) {
    console.log(`${c.pass ? "PASS" : "FAIL"}  ${c.name}${c.detail !== undefined ? `  (${c.detail})` : ""}`);
  }
  process.exit(report.ok ? 0 : 1);
}

function cmdStart() {
  const config = loadConfig();
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
  console.log(pairingUrl(token, config.port));
}

const cmd = process.argv[2] || "start";
if (cmd === "doctor") await cmdDoctor();
else if (cmd === "start") cmdStart();
else {
  console.error(`helmd: unknown command "${cmd}" (expected: start | doctor)`);
  process.exit(1);
}
