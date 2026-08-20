// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-FRESHDB-CRASH-1 regression: a virgin state dir (nothing pre-seeded,
// nothing pre-run) used to crash the daemon on its very first UI poll. The
// dashboard's home view calls GET /ha/pending within seconds of first open;
// that route read straight from `runs` with no write path having created
// the table yet, threw `no such table: runs` uncaught, and the whole daemon
// process exited. `helmd doctor` was 11/11 PASS right before this hit, so
// only a real boot + real HTTP request against a real fresh state dir proves
// it — this spawns the daemon exactly like `cli-verbs.test.mjs` does, but
// unlike that file never pre-seeds a token, so this run is genuinely first-run.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-freshdb-boot-"));
const PORT = 41779;
const ORIGIN = `http://127.0.0.1:${PORT}`;
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "" }));

const ENTRY = join(dirname(fileURLToPath(import.meta.url)), "index.mjs");
const ENV = { ...process.env, HELM_HOME: TMP, HELM_NO_OPEN: "1" };

let daemon;
after(async () => {
  if (daemon && daemon.exitCode === null) {
    const exited = new Promise((resolve) => daemon.once("exit", resolve));
    daemon.kill();
    await exited;
  }
  rmSync(TMP, { recursive: true, force: true });
});

function waitForRunning(child) {
  return new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`daemon did not report ready:\n${out}`)), 20000);
    child.stdout.on("data", (c) => {
      out += c.toString("utf8");
      if (out.includes("Helm is running.")) {
        clearTimeout(timer);
        resolve(out);
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`daemon exited early with code ${code}:\n${out}`));
    });
  });
}

function get(path, headers) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path, method: "GET", headers }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function callDaemonStatus(token) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path: "/health", method: "GET", headers: { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, Authorization: `Bearer ${token}` } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.end();
  });
}

test("daemon survives GET /ha/pending on a virgin state dir, no table pre-created", async () => {
  daemon = spawn(process.execPath, [ENTRY, "start"], { env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  await waitForRunning(daemon);

  // The pairing token is minted by the daemon's own first-run boot, into a
  // file under HELM_HOME — read it back the same way an already-paired
  // browser tab would present it, exactly like server.test.mjs's setup.
  process.env.HELM_HOME = TMP;
  const { loadOrCreateToken } = await import("./token.mjs");
  const token = loadOrCreateToken();

  const headers = { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, Authorization: `Bearer ${token}` };
  const res = await get("/ha/pending", headers);

  assert.equal(daemon.exitCode, null, "daemon process must still be alive after the request");
  assert.equal(res.status, 200, `expected 200, got ${res.status}: ${res.body}`);
  const parsed = JSON.parse(res.body);
  assert.deepEqual(parsed, { pending: [] }, "a fresh install has no runs yet, so the pending queue is empty, not an error");

  // A second poll (the UI polls on an interval) must still succeed — proves
  // the daemon didn't just survive the first hit by luck of ordering.
  const res2 = await get("/ha/pending", headers);
  assert.equal(res2.status, 200);
  assert.equal(await callDaemonStatus(token), 200, "daemon still serving /health after both polls");
});
