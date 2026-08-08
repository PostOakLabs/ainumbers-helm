// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-XOS-CI-1: OS-matrix e2e. Boots helmd's real HTTP server headless,
// replays the pairing bootstrap the browser UI performs (mint token+nonce+fp
// server-side -> parse the #hash with the REAL ui/api.mjs parsers -> POST
// /pair/redeem -> an authenticated call proves "paired"), and asserts the
// OS-specific seams named in the WU: state-dir path, vault/keychain tier
// round-trip, and autostart support/no-op per platform. Runs on
// ubuntu-latest/macos-latest/windows-latest via the xos-e2e matrix job in
// .github/workflows/ci.yml. The dedicated regression test below encodes the
// HELM-PAIR-DIAG-1 finding: a tab that lost its sessionStorage token has no
// self-serve recovery route — this must keep failing the same way, not get
// papered over, on every OS.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-xos-e2e-"));
process.env.HELM_HOME = TMP;
process.env.HELM_NO_OPEN = "1";

const PORT = 41777;
const ORIGIN = `http://127.0.0.1:${PORT}`;

const { statePath } = await import("./state-dir.mjs");
const { loadOrCreateToken, pairingUrl, createPairingNonce } = await import("./token.mjs");
const { loadOrCreateKeys } = await import("./keys.mjs");
const { fingerprintPublicKeyDer } = await import("./challenge.mjs");
const { createHelmServer } = await import("./server.mjs");
const { autostartStatus } = await import("./autostart.mjs");
const { vaultSet, vaultGet } = await import("./vault.mjs");
// The REAL browser-side parsers, not a reimplementation — proves the exact
// code ui/app.mjs's boot() runs actually extracts what pairingUrl() printed.
const { parseTokenFromHash, parsePairFromHash, parseFpFromHash } = await import("../ui/api.mjs");

const token = loadOrCreateToken();
const identityKeys = loadOrCreateKeys();
let server;

before(() => {
  server = createHelmServer({ port: PORT, allowedOrigin: ORIGIN, token, identityKeys });
});

after(() => {
  server.close();
  rmSync(TMP, { recursive: true, force: true });
});

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

function post(path, body, headers) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = request(
      {
        host: "127.0.0.1", port: PORT, path, method: "POST",
        headers: { ...headers, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
      },
      (res) => {
        let resBody = "";
        res.on("data", (c) => (resBody += c));
        res.on("end", () => resolve({ status: res.statusCode, body: resBody }));
      }
    );
    req.on("error", reject);
    req.end(data);
  });
}

function baseHeaders(overrides = {}) {
  return { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN, ...overrides };
}

test(`platform sanity: this run is actually on ${platform()}`, () => {
  assert.ok(["win32", "darwin", "linux"].includes(platform()));
});

test("state-dir: HELM_HOME override resolves under the temp dir on this OS's path scheme", () => {
  const path = statePath("token");
  assert.ok(path.startsWith(TMP), `expected ${path} under ${TMP}`);
});

test("headless boot: GET / serves the shell UI (served-UI mode, not file://)", async () => {
  const res = await get("/", { Host: `127.0.0.1:${PORT}` });
  assert.equal(res.status, 200);
  assert.match(res.body, /<title>Helm<\/title>/);
});

test("pairing bootstrap, replayed exactly as the browser UI performs it end to end", async () => {
  // 1. Mint the pairing URL the CLI prints on boot — same call index.mjs makes.
  const fingerprint = fingerprintPublicKeyDer(
    identityKeys.ed25519.publicKey.export({ format: "der", type: "spki" }).toString("base64")
  );
  const nonce = createPairingNonce();
  const url = pairingUrl(token, PORT, nonce, fingerprint);

  // 2. Parse it with the REAL ui/api.mjs functions, off the #fragment only —
  // the same call shape ui/app.mjs's boot()/readTokenFromLocation() uses.
  const hash = url.slice(url.indexOf("#"));
  const parsedToken = parseTokenFromHash(hash);
  const parsedPair = parsePairFromHash(hash);
  const parsedFp = parseFpFromHash(hash);
  assert.equal(parsedToken, token);
  assert.ok(parsedPair);
  assert.equal(parsedFp, fingerprint);

  // 3. Before pairing completes, an unauthenticated call is refused —
  // "pairing required", matching what the UI's own connectivity check sees.
  const unpaired = await get("/health", baseHeaders());
  assert.equal(unpaired.status, 401);

  // 4. Redeem the nonce exactly as boot() fires POST /pair/redeem —
  // best-effort, using the freshly parsed bearer token.
  const redeem = await post("/pair/redeem", { nonce: parsedPair }, baseHeaders({ Authorization: `Bearer ${parsedToken}` }));
  assert.equal(redeem.status, 200);
  assert.deepEqual(JSON.parse(redeem.body), { ok: true });

  // 5. "Paired" state, asserted the same way the UI checks connectivity: an
  // authenticated GET now succeeds.
  const paired = await get("/health", baseHeaders({ Authorization: `Bearer ${parsedToken}` }));
  assert.equal(paired.status, 200);
  assert.equal(JSON.parse(paired.body).status, "ok");
});

// HELM-PAIR-DIAG-1's diagnosed regression: the pairing token lives ONLY in
// sessionStorage (ui/api.mjs saveToken/saveFp), and 2026.8.4 stopped
// auto-opening a fresh tab on ordinary restarts — so a tab close/reopen (or
// any new tab with no #hash) has no token and no route back in through the
// UI on its own. This is the positive control the WU asks for: prove the
// failure is real, and stays real, on THIS OS.
test("REGRESSION (HELM-PAIR-DIAG-1): a tab with no sessionStorage token has no self-serve recovery route", async () => {
  // A fresh "tab" — no #hash was ever present, so nothing was parsed/saved.
  const noToken = await get("/health", baseHeaders());
  assert.equal(noToken.status, 401, "an unauthenticated tab must see pairing-required, matching the real symptom");

  // The one recovery route that exists, /pair/relink, itself requires the
  // durable bearer it would be minting a fresh path back to — so a tab that
  // lost the token cannot self-serve out of this state. Confirming this
  // diagnosed dead end stays true is the point of this test, not a bug in it.
  const relinkWithoutToken = await post("/pair/relink", {}, baseHeaders());
  assert.equal(relinkWithoutToken.status, 401, "relink itself requires the token it would help recover — no route back without it");
});

// --- OS-specific seams (WU: "state-dir paths, keychain/vault fallback, autostart no-ops") ---

test(`autostart: platform-correct support flag on ${platform()}`, () => {
  const status = autostartStatus();
  const expectSupported = platform() === "darwin" || platform() === "win32";
  assert.equal(status.supported, expectSupported, `autostart.supported must match this OS (${platform()})`);
  if (!expectSupported) {
    assert.equal(status.reason, "unsupported");
  } else {
    // Fresh HELM_HOME, nothing ever POSTed /autostart in this run — the real
    // per-OS reader (registry query / LaunchAgent plist check) must agree.
    assert.equal(status.installed, false);
    assert.equal(status.reason, "not_installed");
  }
});

test("vault: a secret set/get round-trips through whichever tier is native to this OS, or the file-fallback tier", () => {
  const ref = "vault://helm-xos-e2e/roundtrip";
  const result = vaultSet(ref, { value: "xos-e2e-secret" });
  assert.ok(
    ["macos-keychain", "windows-dpapi", "linux-secret-tool", "file-fallback"].includes(result.backend),
    `unexpected vault backend: ${result.backend}`
  );
  const read = vaultGet(ref);
  assert.equal(read?.value, "xos-e2e-secret");
});
