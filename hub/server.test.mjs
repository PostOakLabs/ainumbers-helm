import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request, createServer } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-test-"));
process.env.HELM_HOME = TMP;

const PORT = 41999;
const ORIGIN = "null";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken, createPairingNonce } = await import("./token.mjs");
const { loadOrCreateKeys } = await import("./keys.mjs");
const { verifyChallenge } = await import("./challenge.mjs");
const { createHelmServer, bindOrExit, MAX_SSE_CONNECTIONS, DAEMON_VERSION, SUPPORTED_API_VERSIONS } = await import("./server.mjs");

const config = loadConfig();
const token = loadOrCreateToken();
const identityKeys = loadOrCreateKeys();
let server;

before(() => {
  server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token, identityKeys });
});

after(() => {
  server.close();
  rmSync(TMP, { recursive: true, force: true });
});

// node:http.request lets us set an arbitrary Host header (fetch forbids it),
// which is exactly what's needed to simulate a DNS-rebound request.
function get(path, headers) {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: PORT, path, method: "GET", headers },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function post(path, body, headers) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = request(
      {
        host: "127.0.0.1",
        port: PORT,
        path,
        method: "POST",
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

function headers(overrides = {}) {
  return {
    Host: `127.0.0.1:${PORT}`,
    Origin: ORIGIN,
    Authorization: `Bearer ${token}`,
    ...overrides,
  };
}

test("valid request succeeds", async () => {
  const res = await get("/health", headers());
  assert.equal(res.status, 200);
  assert.equal(JSON.parse(res.body).status, "ok");
});

test("negative: tokenless request rejected", async () => {
  const h = headers();
  delete h.Authorization;
  const res = await get("/health", h);
  assert.equal(res.status, 401);
});

test("negative: wrong token rejected", async () => {
  const res = await get("/health", headers({ Authorization: "Bearer wrong" }));
  assert.equal(res.status, 401);
});

test("negative: cross-origin fetch rejected", async () => {
  const res = await get("/health", headers({ Origin: "https://evil.example" }));
  assert.equal(res.status, 403);
});

test("negative: DNS-rebind Host rejected", async () => {
  // Simulates a browser that resolved evil.example -> 127.0.0.1 (DNS
  // rebinding) and so still sends the attacker hostname in Host.
  const res = await get("/health", headers({ Host: "evil.example" }));
  assert.equal(res.status, 403);
});

test("GET /vault/connections is authenticated and starts empty", async () => {
  const res = await get("/vault/connections", headers());
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { connections: [] });
});

test("GET /vault/connections/flow/:id 404s for an unknown flow", async () => {
  const res = await get("/vault/connections/flow/does-not-exist", headers());
  assert.equal(res.status, 404);
});

test("GET /kernels/:id/card returns a JSON kernel validation card (HELM-P3-E12)", async () => {
  const res = await get("/kernels/art-298-aca-affordability-safe-harbor/card", headers());
  assert.equal(res.status, 200);
  const card = JSON.parse(res.body);
  assert.equal(card.kernel_id, "art-298-aca-affordability-safe-harbor");
  assert.ok(card.test_vectors.length > 0);
  assert.match(card.kernel_digest, /^sha256:[0-9a-f]{64}$/);
});

test("GET /kernels/:id/card?format=html returns a printable HTML document (HELM-P3-E12)", async () => {
  const res = await get("/kernels/art-298-aca-affordability-safe-harbor/card?format=html", headers());
  assert.equal(res.status, 200);
  assert.match(res.body, /<!doctype html>/);
  assert.match(res.body, /art-298-aca-affordability-safe-harbor/);
});

test("GET /kernels/:id/card 404s for an unknown kernel", async () => {
  const res = await get("/kernels/does-not-exist/card", headers());
  assert.equal(res.status, 404);
});

test("GET /workflows/:id/euc-entry returns a JSON EUC register entry (HELM-P3-E12)", async () => {
  const res = await get(
    "/workflows/pack-aca-226j-response-composer/euc-entry?owner=Compliance&last_validated=2026-07-01",
    headers()
  );
  assert.equal(res.status, 200);
  const entry = JSON.parse(res.body);
  assert.equal(entry.workflow_id, "pack-aca-226j-response-composer");
  assert.equal(entry.kernels.length, 3);
  assert.equal(entry.owner, "Compliance");
  assert.equal(entry.last_validated, "2026-07-01");
});

test("GET /workflows/:id/euc-entry?format=html returns a printable HTML document (HELM-P3-E12)", async () => {
  const res = await get("/workflows/pack-aca-226j-response-composer/euc-entry?format=html", headers());
  assert.equal(res.status, 200);
  assert.match(res.body, /<!doctype html>/);
  assert.match(res.body, /pack-aca-226j-response-composer/);
});

test("GET /workflows/:id/euc-entry 404s for an unknown workflow", async () => {
  const res = await get("/workflows/does-not-exist/euc-entry", headers());
  assert.equal(res.status, 404);
});

test("negative: POST /vault/connections/begin with http tokenEndpoint rejected (F4)", async () => {
  const res = await post(
    "/vault/connections/begin",
    {
      provider: "test",
      authorizationEndpoint: "https://provider.example/authorize",
      tokenEndpoint: "http://provider.example/token",
      clientId: "abc",
      scopes: ["read"],
    },
    headers()
  );
  assert.equal(res.status, 400);
  assert.equal(JSON.parse(res.body).error, "insecure_endpoint");
});

test("HELM-SEC-5 hardening: /events refuses a connection past MAX_SSE_CONNECTIONS", async () => {
  const openReqs = [];
  const openConns = [];
  const openSse = (n) =>
    new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: PORT, path: "/events", method: "GET", headers: headers() });
      req.on("socket", (socket) => openConns.push(socket));
      req.on("response", (res) => resolve(res.statusCode));
      req.on("error", reject);
      req.end();
      openReqs.push(req);
    });

  try {
    for (let i = 0; i < MAX_SSE_CONNECTIONS; i++) {
      const status = await openSse(i);
      assert.equal(status, 200, `connection ${i} should be accepted`);
    }
    const overflowStatus = await openSse(MAX_SSE_CONNECTIONS);
    assert.equal(overflowStatus, 503, "connection past the cap should be refused");
  } finally {
    for (const socket of openConns) socket.destroy();
  }
});

// HELM-U4: served-UI shell. Deliberately no Origin/Authorization headers —
// a real top-level navigation can't send either.
test("static: GET / serves the shell UI with no Origin/Authorization headers", async () => {
  const res = await get("/", { Host: `127.0.0.1:${PORT}` });
  assert.equal(res.status, 200);
  assert.match(res.body, /<title>Helm<\/title>/);
});

test("static: GET /app.mjs serves as a JS module, no auth required", async () => {
  const res = await get("/app.mjs", { Host: `127.0.0.1:${PORT}` });
  assert.equal(res.status, 200);
});

test("static: CSP blocks inline script (no unsafe-inline, script-src 'self')", async () => {
  const res = await new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path: "/", method: "GET", headers: { Host: `127.0.0.1:${PORT}` } }, resolve);
    req.on("error", reject);
    req.end();
  });
  const csp = res.headers["content-security-policy"];
  assert.ok(csp, "CSP header must be present");
  assert.doesNotMatch(csp, /unsafe-inline/);
  assert.match(csp, /script-src 'self'/);
});

test("static: nosniff + no cookie on every static response", async () => {
  const res = await new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path: "/theme.css", method: "GET", headers: { Host: `127.0.0.1:${PORT}` } }, resolve);
    req.on("error", reject);
    req.end();
  });
  assert.equal(res.headers["x-content-type-options"], "nosniff");
  assert.equal(res.headers["set-cookie"], undefined);
});

test("static: traversal-style path is not servable, falls through to normal 404", async () => {
  const res = await get("/../../hub/token.mjs", headers());
  assert.equal(res.status, 404);
  assert.equal(JSON.parse(res.body).error, "not_found");
});

test("static: unknown path under a real UI directory (e.g. /views/does-not-exist.mjs) 404s, not served", async () => {
  const res = await get("/views/does-not-exist.mjs", headers());
  assert.equal(res.status, 404);
});

// HELM-P2-LAUNCH regression: app.mjs statically imports every entry in
// VIEWS (including help), so each one must be in ui-manifest's FILES
// allowlist or the whole ES module graph 401s and <main> never mounts —
// the same failure mode already documented for fixtures/verify-demo.mjs.
test("static: GET /views/help.mjs serves as a JS module, no auth required (regression: was missing from ui-manifest FILES)", async () => {
  const res = await get("/views/help.mjs", { Host: `127.0.0.1:${PORT}` });
  assert.equal(res.status, 200);
});

// Served-UI mode: allowedOrigin is a real http://127.0.0.1:port origin, so a
// request presenting the old file:// "null" Origin must be rejected — that
// legacy allowance is gone (HELM-U4 item 5). Own server + own port: the rest
// of this file deliberately configures allowedOrigin: "null" to cover the
// pre-U4 shape, so this needs a second instance with a real origin to prove
// "null" is no longer accepted anywhere.
test("negative: null Origin rejected against a served-UI (non-null) allowedOrigin", async () => {
  const port2 = PORT + 1;
  const origin2 = `http://127.0.0.1:${port2}`;
  const server2 = createHelmServer({ port: port2, allowedOrigin: origin2, token });
  try {
    const res = await new Promise((resolve, reject) => {
      const req = request(
        { host: "127.0.0.1", port: port2, path: "/health", method: "GET", headers: { Host: `127.0.0.1:${port2}`, Origin: "null", Authorization: `Bearer ${token}` } },
        (r) => {
          let body = "";
          r.on("data", (c) => (body += c));
          r.on("end", () => resolve({ status: r.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(res.status, 403);
    assert.equal(JSON.parse(res.body).error, "origin_mismatch");
  } finally {
    server2.close();
  }
});

test("negative: POST /vault/connections/begin with http authorizationEndpoint rejected (F4)", async () => {
  const res = await post(
    "/vault/connections/begin",
    {
      provider: "test",
      authorizationEndpoint: "http://provider.example/authorize",
      tokenEndpoint: "https://provider.example/token",
      clientId: "abc",
      scopes: ["read"],
    },
    headers()
  );
  assert.equal(res.status, 400);
  assert.equal(JSON.parse(res.body).error, "insecure_endpoint");
});

// --- HELM-P3-H6: detection + handoff + pairing hardening ---

const DETECTION_ORIGIN = "https://ainumbers.co";

test("GET /version: reachable from the hosted origin with NO bearer token (P3-D3 detection surface)", async () => {
  const res = await get("/version", { Host: `127.0.0.1:${PORT}`, Origin: DETECTION_ORIGIN });
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  assert.equal(body.daemon, DAEMON_VERSION);
  assert.deepEqual(body.api, SUPPORTED_API_VERSIONS);
});

test("GET /version: still reachable from the loopback UI's own origin (no bearer needed there either)", async () => {
  const res = await get("/version", { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN });
  assert.equal(res.status, 200);
});

test("negative: GET /version from an arbitrary third-party origin rejected", async () => {
  const res = await get("/version", { Host: `127.0.0.1:${PORT}`, Origin: "https://evil.example" });
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body).error, "origin_mismatch");
});

test("OPTIONS /version: answers the Private Network Access preflight for the hosted origin", async () => {
  const res = await new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: PORT, path: "/version", method: "OPTIONS", headers: { Host: `127.0.0.1:${PORT}`, Origin: DETECTION_ORIGIN } },
      (r) => resolve(r)
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(res.statusCode, 204);
  assert.equal(res.headers["access-control-allow-private-network"], "true");
  assert.equal(res.headers["access-control-allow-origin"], DETECTION_ORIGIN);
});

test("GET /pair/challenge: signed with the daemon's identity key, verifiable, no bearer required", async () => {
  const res = await get("/pair/challenge", { Host: `127.0.0.1:${PORT}`, Origin: DETECTION_ORIGIN });
  assert.equal(res.status, 200);
  const challenge = JSON.parse(res.body);
  assert.ok(challenge.nonce && challenge.signature && challenge.publicKey);
  assert.equal(verifyChallenge(challenge), true);
});

test("GET /pair/challenge: 503 when the daemon has no identity keys configured", async () => {
  const port2 = PORT + 2;
  const server2 = createHelmServer({ port: port2, allowedOrigin: `http://127.0.0.1:${port2}`, token });
  try {
    const res = await new Promise((resolve, reject) => {
      const req = request(
        { host: "127.0.0.1", port: port2, path: "/pair/challenge", method: "GET", headers: { Host: `127.0.0.1:${port2}`, Origin: DETECTION_ORIGIN } },
        (r) => {
          let body = "";
          r.on("data", (c) => (body += c));
          r.on("end", () => resolve({ status: r.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(res.status, 503);
  } finally {
    server2.close();
  }
});

test("POST /pair/redeem: single-use — first redeem succeeds, replay of the same nonce fails", async () => {
  const nonce = createPairingNonce();
  const first = await post("/pair/redeem", { nonce }, headers());
  assert.equal(first.status, 200);
  assert.deepEqual(JSON.parse(first.body), { ok: true });
  const replay = await post("/pair/redeem", { nonce }, headers());
  assert.equal(replay.status, 401);
  assert.equal(JSON.parse(replay.body).error, "pairing_expired_or_used");
});

test("POST /pair/redeem: unknown nonce rejected", async () => {
  const res = await post("/pair/redeem", { nonce: "never-issued" }, headers());
  assert.equal(res.status, 401);
});

test("POST /pair/redeem: an expired nonce (short TTL, injected clock) is rejected", async () => {
  const nonce = createPairingNonce(Date.now() - 10 * 60 * 1000); // minted "10 minutes ago"
  const res = await post("/pair/redeem", { nonce }, headers());
  assert.equal(res.status, 401);
});

test("negative: GET /pair/challenge from an arbitrary third-party origin rejected", async () => {
  const res = await get("/pair/challenge", { Host: `127.0.0.1:${PORT}`, Origin: "https://evil.example" });
  assert.equal(res.status, 403);
});

test("negative: POST to a detection-surface path (not GET/OPTIONS) 404s rather than falling through to the authed router", async () => {
  const res = await post("/version", {}, { Host: `127.0.0.1:${PORT}`, Origin: DETECTION_ORIGIN });
  assert.equal(res.status, 404);
});

test("bindOrExit: squatted port is refused cleanly, never falls back to a different port", async () => {
  const port3 = PORT + 3;
  // Occupy the port first, simulating another process already bound there.
  const squatter = createServer();
  await new Promise((resolve) => squatter.listen(port3, "127.0.0.1", resolve));
  try {
    const server3 = createHelmServer({ port: port3, allowedOrigin: `http://127.0.0.1:${port3}`, token });
    const bound = await bindOrExit(server3, port3);
    assert.equal(bound, false);
    // server3 never bound (EADDRINUSE) — closing an unlistened http.Server
    // emits its own async 'error' with no listener attached, which is an
    // uncaught exception in Node. Nothing to close; it never opened.
  } finally {
    await new Promise((resolve) => squatter.close(resolve));
  }
});

test("bindOrExit: a free port binds successfully", async () => {
  const port4 = PORT + 4;
  const server4 = createHelmServer({ port: port4, allowedOrigin: `http://127.0.0.1:${port4}`, token });
  try {
    const bound = await bindOrExit(server4, port4);
    assert.equal(bound, true);
  } finally {
    server4.close();
  }
});
