#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// `helmd matter-close <matter_id>` (HELM-MATTER-H2, HELM-MATTER-BUILD-SPEC.md
// §5): the CLI trigger path so an external tool's own closeout event (the
// row's "gateway-log-demo pattern, legal edition" — CounselOS's own
// git-commit-on-closeout is the reference shape) can call Helm's matter
// export — e.g. a git post-commit hook shelling out to this command on the
// same event that commits the matter file. Ships correctly with NO external
// tool ever calling this: it is exactly as useful run by hand as it is from
// another tool's hook, and helmd never depends on the integration existing.
//
// A thin authenticated HTTP client against the ALREADY-RUNNING daemon —
// reuses POST /matters/{id}/update verbatim (the same Host+Origin+Bearer D8
// gate every other caller passes, the same route the paired UI/REST API
// already exposes), rather than opening a second connection to helmd's own
// SQLite file. helmd owns that file, one process, one writer (journal.mjs's
// header comment, D4/H4) — a second process reading/writing it directly
// while the daemon is live is exactly the hazard this design avoids.
// Requires helmd to be running; if it isn't, this fails with a clear
// connection message rather than attempting to open the state directory
// itself. Token/config are read the same way the paired browser UI's own
// credentials are sourced — a local file read, same trust boundary as
// reading ~/.helm/keys.enc.json (token.mjs's loadOrCreateToken doc comment).
import { writeFileSync } from "node:fs";
import { loadConfig } from "../hub/config.mjs";
import { loadOrCreateToken } from "../hub/token.mjs";

function usage() {
  console.error("usage: helmd matter-close <matter_id> [--out <export.json>] [--json]");
}

const rawArgs = process.argv.slice(2);
const flags = new Set();
const positional = [];
let outPath;
for (let i = 0; i < rawArgs.length; i++) {
  const a = rawArgs[i];
  if (a === "--out") { outPath = rawArgs[++i]; continue; }
  if (a.startsWith("--")) { flags.add(a); continue; }
  positional.push(a);
}
const [matterId] = positional;
const jsonMode = flags.has("--json");

if (!matterId) {
  usage();
  process.exit(2);
}

const { port, allowedOrigin } = loadConfig();
const token = loadOrCreateToken();

let res;
try {
  res = await fetch(`http://127.0.0.1:${port}/matters/${encodeURIComponent(matterId)}/update`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: allowedOrigin, Authorization: `Bearer ${token}` },
    body: JSON.stringify({ status: "closed" }),
  });
} catch (err) {
  console.error(`helmd matter-close: could not reach helmd on 127.0.0.1:${port} — is it running? (${String(err?.message || err)})`);
  process.exit(1);
}

let body;
try {
  body = await res.json();
} catch {
  body = {};
}

if (!res.ok || body.ok !== true) {
  console.error(`helmd matter-close: refused (HTTP ${res.status}) — ${body.error ?? "unknown error"}`);
  process.exit(1);
}

if (body.export && outPath) {
  writeFileSync(outPath, JSON.stringify(body.export, null, 2) + "\n");
}

if (jsonMode) {
  console.log(JSON.stringify(body));
} else {
  console.log(`Matter ${matterId}: status now "${body.matter.status}".`);
  if (body.export) {
    console.log(`Signed closeout export emitted (envelope digest ${body.export.envelope_digest}).`);
    if (outPath) console.log(`Export written to ${outPath}`);
  } else {
    console.log("(no new export emitted — matter was already closed before this call)");
  }
}
