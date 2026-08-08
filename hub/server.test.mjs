import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request, createServer } from "node:http";
import { generateKeyPairSync } from "node:crypto";

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
const { openJournal } = await import("./journal.mjs");
const { vaultSet } = await import("./vault.mjs");
const { __setHostResolverForTest } = await import("./connector.mjs");
const { __setManifestOverrideForTest } = await import("./run-actions.mjs");
const { subscribeRunEvents } = await import("./event-bus.mjs");
const { log } = await import("./log.mjs");

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

// The bearer token rides in the query string on /events (EventSource can't
// set an Authorization header), so a rejected request must never log req.url
// verbatim — that writes a WORKING credential to stdout, which the macOS
// LaunchAgent can capture to a file. Both reject paths are covered: the host
// gate (which fires before pathname is computed) and the origin gate.
test("negative: a rejected /events request never logs the token", async () => {
  const written = [];
  const realWrite = process.stdout.write.bind(process.stdout);
  // Suppressed rather than tee'd on purpose: if this assertion ever fails, we
  // do not want the leaked credential printed into CI output as well.
  process.stdout.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    await get(`/events?token=${token}`, headers({ Host: "evil.example" }));
    await get(`/events?token=${token}`, headers({ Origin: "https://evil.example" }));
  } finally {
    process.stdout.write = realWrite;
  }
  const logged = written.join("");
  assert.ok(logged.includes("rejected:"), "expected the rejections to be logged at all");
  assert.ok(!logged.includes(token), "bearer token leaked into log output");
  assert.ok(logged.includes("/events"), "expected the path itself to still be logged");
});

// HELM-REPAIR-LINK-1 (HELM-PAIR-DIAG-1 proposal 3): a bare browser GET of
// /favicon.ico can never carry a bearer token, so it 401s on every page
// load regardless of pairing state — quieted to stop drowning real 401s
// during triage, but ONLY for that one path; every other rejected path
// must still warn (regression cover for accidentally silencing the gate).
test("GET /favicon.ico: 401s same as any unauthenticated route, but is not logged", async () => {
  // Spies on log.warn itself, not process.stdout.write — the test runner's
  // own reporter also writes to stdout mid-test (its progress line for
  // THIS test's title contains the literal substring "/favicon.ico"),
  // which false-failed a stdout-capture version of this assertion.
  const calls = [];
  const realWarn = log.warn;
  log.warn = (msg, fields) => calls.push({ msg, fields });
  let res;
  try {
    res = await get("/favicon.ico", { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN });
    await get("/health", { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN }); // no Authorization — still must log
  } finally {
    log.warn = realWarn;
  }
  assert.equal(res.status, 401);
  assert.ok(!calls.some((c) => c.fields?.path === "/favicon.ico"), "favicon rejection should not be logged");
  assert.ok(calls.some((c) => c.fields?.path === "/health"), "a genuine unauthenticated rejection on another path must still be logged");
});

test("GET /vault/connections is authenticated and starts empty", async () => {
  const res = await get("/vault/connections", headers());
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { connections: [] });
});

// HELM-BIND-3 §4.2: before this route existed, ui/views/connect.mjs's fetch
// to "/connectors" hit the generic 404 every other undefined path gets —
// the Connect tab's "Daemon connectors" section could never render anything
// but a blocked-state card. This is the route ui/views/connect.mjs's
// fetchWithFallback("/connectors", ...) call already expects: {connectors:
// [{contract, status}]}, one entry per bundled connector contract, in the
// exact shape connectorCard() in that view reads.
test("GET /connectors: lists the bundled connector contracts in the shape the Connect tab reads", async () => {
  const res = await get("/connectors", headers());
  assert.equal(res.status, 200);
  const body = JSON.parse(res.body);
  const ids = body.connectors.map((e) => e.contract.connector_id).sort();
  assert.deepEqual(ids, ["google-drive.fetch", "http.send", "inbound-webhook", "smtp.send"]);
  for (const entry of body.connectors) {
    assert.ok(Array.isArray(entry.contract.allowed_hosts) && entry.contract.allowed_hosts.length > 0);
    assert.ok(Array.isArray(entry.contract.allowed_methods) && entry.contract.allowed_methods.length > 0);
    assert.equal(typeof entry.status, "string");
  }
});

test("negative: GET /connectors is authenticated like every other route", async () => {
  const h = headers();
  delete h.Authorization;
  const res = await get("/connectors", h);
  assert.equal(res.status, 401);
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

test("GET /workflows/:id/export returns a versioned, secrets-stripped .helm.json (HELM-P3-W11)", async () => {
  const res = await get("/workflows/pack-aca-226j-response-composer/export", headers());
  assert.equal(res.status, 200);
  const doc = JSON.parse(res.body);
  assert.equal(doc.format_version, "1");
  assert.equal(doc.result, "ok");
  assert.equal(doc.secrets_stripped, true);
  assert.equal(doc.kernel_pins.length, 3);
  assert.match(doc.workflow_manifest_digest, /^sha256:[0-9a-f]{64}$/);
});

test("GET /workflows/:id/export 404s for an unknown workflow", async () => {
  const res = await get("/workflows/does-not-exist/export", headers());
  assert.equal(res.status, 404);
});

// HELM-BPMN-WIRE-1: exportBpmn (hub/bpmn-export.mjs) was CLI-only
// (scripts/export-bpmn.mjs) with no daemon route reaching it. This wires it
// onto the existing GET /workflows/:id/export surface via ?format=bpmn,
// same read-tier auth as the .helm.json export above (no consent ticket —
// it's a diagram of a workflow the user already has, no secret material).
test("GET /workflows/:id/export?format=bpmn returns BPMN 2.0 XML (HELM-BPMN-WIRE-1)", async () => {
  const res = await get("/workflows/pack-aca-226j-response-composer/export?format=bpmn", headers());
  assert.equal(res.status, 200);
  assert.match(res.body, /^<\?xml version="1\.0"/);
  assert.match(res.body, /<bpmn:definitions/);
  assert.match(res.body, /<bpmn:process/);
});

test("GET /workflows/:id/export?format=bpmn 404s for an unknown workflow (HELM-BPMN-WIRE-1)", async () => {
  const res = await get("/workflows/does-not-exist/export?format=bpmn", headers());
  assert.equal(res.status, 404);
});

test("POST /workflows/import round-trips a freshly exported workflow (HELM-P3-W11)", async () => {
  const exportRes = await get("/workflows/pack-aca-226j-response-composer/export", headers());
  const exported = JSON.parse(exportRes.body);
  const res = await post("/workflows/import", { export: exported }, headers());
  assert.equal(res.status, 200);
  const result = JSON.parse(res.body);
  assert.equal(result.ok, true);
  assert.equal(result.workflow_id, "pack-aca-226j-response-composer");
  assert.deepEqual(result.manifest, exported.workflow_manifest);
});

test("POST /workflows/import refuses an unsupported format_version, explained not silently mangled (HELM-P3-W11)", async () => {
  const exportRes = await get("/workflows/pack-aca-226j-response-composer/export", headers());
  const exported = JSON.parse(exportRes.body);
  const res = await post("/workflows/import", { export: { ...exported, format_version: "9" } }, headers());
  assert.equal(res.status, 422);
  const result = JSON.parse(res.body);
  assert.equal(result.result, "refused");
  assert.equal(result.minimum_supported_version, "1");
  assert.match(result.reason, /unsupported format_version/);
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

// HELM-UX-1 §7.4: /events must accept a short-lived ticket instead of the
// durable bearer riding in the query string for the life of a session.
test("§7.4: a minted ticket authenticates /events, and only once", async () => {
  const minted = await post("/events/ticket", {}, headers());
  assert.equal(minted.status, 200);
  const { ticket } = JSON.parse(minted.body);
  assert.ok(ticket, "expected a ticket in the response");

  await new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port: PORT, path: `/events?ticket=${ticket}`, method: "GET", headers: { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN } });
    req.on("response", (res) => {
      assert.equal(res.statusCode, 200);
      req.destroy();
      resolve();
    });
    req.on("error", reject);
    req.end();
  });

  // Single-use: the same ticket must not authenticate a second connection.
  const replay = await get(`/events?ticket=${ticket}`, { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN });
  assert.equal(replay.status, 401);
});

test("negative: an unknown /events ticket is rejected", async () => {
  const res = await get("/events?ticket=not-a-real-ticket", { Host: `127.0.0.1:${PORT}`, Origin: ORIGIN });
  assert.equal(res.status, 401);
});

// HELM-UX-1 §8: Operate view Quit button. Uses an isolated server instance
// with an injected exitFn so the test process itself never calls
// process.exit() — a real exitFn is only ever wired in production (helmd's
// own entrypoint).
test("§8: POST /shutdown replies before exiting, then calls exitFn", async () => {
  const SHUTDOWN_PORT = 42000;
  let exited = false;
  const shutdownServer = createHelmServer({
    port: SHUTDOWN_PORT,
    allowedOrigin: ORIGIN,
    token,
    identityKeys,
    exitFn: () => { exited = true; },
  });
  try {
    const res = await new Promise((resolve, reject) => {
      const data = JSON.stringify({});
      const req = request(
        { host: "127.0.0.1", port: SHUTDOWN_PORT, path: "/shutdown", method: "POST", headers: { ...headers({ Host: `127.0.0.1:${SHUTDOWN_PORT}` }), "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } },
        (res) => {
          let body = "";
          res.on("data", (c) => (body += c));
          res.on("end", () => resolve({ status: res.statusCode, body }));
        }
      );
      req.on("error", reject);
      req.end(data);
    });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).stopping, true);
    assert.equal(exited, false, "must reply before exiting");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(exited, true, "exitFn should run shortly after the reply");
  } finally {
    shutdownServer.close();
  }
});

test("§18: GET /health announces idleTimeoutMs", async () => {
  const IDLE_PORT = 42003;
  const idleServer = createHelmServer({
    port: IDLE_PORT, allowedOrigin: ORIGIN, token, identityKeys, idleTimeoutMs: 5000,
  });
  try {
    const res = await new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: IDLE_PORT, path: "/health", method: "GET", headers: headers({ Host: `127.0.0.1:${IDLE_PORT}` }) }, (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, body }));
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).idleTimeoutMs, 5000);
  } finally {
    idleServer.close();
  }
});

test("§18.2: onAuthenticated fires once per authenticated request, not on a rejected one", async () => {
  const AUTH_PORT = 42004;
  let calls = 0;
  const authServer = createHelmServer({
    port: AUTH_PORT, allowedOrigin: ORIGIN, token, identityKeys, onAuthenticated: () => calls++,
  });
  try {
    await new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: AUTH_PORT, path: "/health", method: "GET", headers: { Host: `127.0.0.1:${AUTH_PORT}`, Origin: ORIGIN } }, (res) => {
        res.on("data", () => {});
        res.on("end", resolve);
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(calls, 0, "a request with no bearer token must not reset the idle timer");
    await new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port: AUTH_PORT, path: "/health", method: "GET", headers: headers({ Host: `127.0.0.1:${AUTH_PORT}` }) }, (res) => {
        res.on("data", () => {});
        res.on("end", resolve);
      });
      req.on("error", reject);
      req.end();
    });
    assert.equal(calls, 1);
  } finally {
    authServer.close();
  }
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
test("static: GET /views/learn.mjs serves as a JS module, no auth required (regression: was missing from ui-manifest FILES)", async () => {
  const res = await get("/views/learn.mjs", { Host: `127.0.0.1:${PORT}` });
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

// --- HELM-ORIGIN-1: same-origin GET requests carry no Origin header at all
// (fetch spec omits it for same-origin GET/HEAD) and Referrer-Policy:
// no-referrer (static.mjs) rules out Referer as a fallback too — Sec-Fetch-
// Site is the only browser-guaranteed, JS-unspoofable signal left standing.

test("GET /health with NO Origin header but Sec-Fetch-Site: same-origin succeeds (real browser same-origin GET shape)", async () => {
  const res = await get("/health", { Host: `127.0.0.1:${PORT}`, Authorization: `Bearer ${token}`, "Sec-Fetch-Site": "same-origin" });
  assert.equal(res.status, 200);
});

test("negative: GET /health with NO Origin header and NO Sec-Fetch-Site header stays rejected (fail-closed unchanged)", async () => {
  const res = await get("/health", { Host: `127.0.0.1:${PORT}`, Authorization: `Bearer ${token}` });
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body).error, "origin_mismatch");
});

test("negative: GET /health with NO Origin header but Sec-Fetch-Site: cross-site is rejected", async () => {
  const res = await get("/health", { Host: `127.0.0.1:${PORT}`, Authorization: `Bearer ${token}`, "Sec-Fetch-Site": "cross-site" });
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body).error, "origin_mismatch");
});

test("negative: a present-but-wrong Origin is never forgiven by the Sec-Fetch-Site fallback", async () => {
  const res = await get("/health", { Host: `127.0.0.1:${PORT}`, Origin: "https://evil.example", Authorization: `Bearer ${token}`, "Sec-Fetch-Site": "same-origin" });
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body).error, "origin_mismatch");
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

// HELM-ORIGIN-1: the detection surface has the same same-origin-GET blind
// spot — the loopback UI's own real-browser GET /version omits Origin too.
test("GET /version: NO Origin header but Sec-Fetch-Site: same-origin succeeds, and echoes allowedOrigin (not undefined) in CORS", async () => {
  const res = await new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port: PORT, path: "/version", method: "GET", headers: { Host: `127.0.0.1:${PORT}`, "Sec-Fetch-Site": "same-origin" } },
      (r) => {
        let body = "";
        r.on("data", (c) => (body += c));
        r.on("end", () => resolve({ status: r.statusCode, body, headers: r.headers }));
      }
    );
    req.on("error", reject);
    req.end();
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers["access-control-allow-origin"], ORIGIN);
});

test("negative: GET /version with NO Origin and NO Sec-Fetch-Site stays rejected", async () => {
  const res = await get("/version", { Host: `127.0.0.1:${PORT}` });
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

test("POST /pair/relink: unauthenticated request rejected (mints nothing without the existing bearer)", async () => {
  const h = headers();
  delete h.Authorization;
  const res = await post("/pair/relink", {}, h);
  assert.equal(res.status, 401);
});

test("POST /pair/relink: mints a fresh pairing URL carrying the SAME durable token, a NEW single-use nonce, and the daemon's fingerprint", async () => {
  const res = await post("/pair/relink", {}, headers());
  assert.equal(res.status, 200);
  const { url } = JSON.parse(res.body);
  assert.match(url, new RegExp(`^http://127\\.0\\.0\\.1:${PORT}/#token=${token}&pair=[0-9a-f]{32}&fp=sha256:[0-9a-f]{64}$`));

  // The minted nonce is real and single-use through the ordinary /pair/redeem
  // path — not a decorative value tacked onto the URL.
  const nonce = /&pair=([0-9a-f]{32})/.exec(url)[1];
  const redeemed = await post("/pair/redeem", { nonce }, headers());
  assert.equal(redeemed.status, 200);
  const replay = await post("/pair/redeem", { nonce }, headers());
  assert.equal(replay.status, 401);
});

test("POST /pair/relink: two mints in a row never reuse the same nonce", async () => {
  const a = JSON.parse((await post("/pair/relink", {}, headers())).body).url;
  const b = JSON.parse((await post("/pair/relink", {}, headers())).body).url;
  assert.notEqual(a, b);
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

// --- HELM-AUTOSTART-1: the consent-gated autostart routes ---
//
// These run against their OWN server on their OWN port with FAKE autostart
// ops. Two reasons: the injected ops mean no test can touch the developer's
// real registry or Start Menu, and a per-test recorder lets a rejection test
// assert the stronger thing — that the write never happened — instead of only
// that the status code was 403.
//
// The spec's warning is the point of this block: do NOT assume the shared
// Host+Origin+Bearer gate covers a brand-new route transitively. A route added
// to the pre-auth static allowlist or the detection carve-out by mistake would
// still 200 happily; the only way to know is to aim each rejection at THIS
// path.
function fakeAutostartOps() {
  const calls = [];
  let installed = false;
  let shortcut = false;
  return {
    calls,
    ops: {
      status: () => ({
        supported: true,
        installed,
        stale: false,
        reason: installed ? "ok" : "not_installed",
        location: "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AINumbersHelmd",
        recorded: installed ? '"C:\helmd.exe" "start"' : null,
      }),
      install: () => {
        calls.push("install");
        installed = true;
        return { ok: true };
      },
      uninstall: () => {
        calls.push("uninstall");
        installed = false;
        return { ok: true };
      },
      shortcutStatus: () => ({ installed: shortcut, location: "C:\Start Menu\Helm.lnk" }),
      installShortcut: () => {
        calls.push("installShortcut");
        shortcut = true;
        return { ok: true };
      },
      uninstallShortcut: () => {
        calls.push("uninstallShortcut");
        shortcut = false;
        return { ok: true };
      },
    },
  };
}

// Each test gets its OWN port: server.close() does not settle before the next
// test starts listening, and the shared-port version of this block failed with
// ECONNRESET on every second test.
let asPortSeq = PORT + 5;

function asRequest(port, { method = "GET", path = "/autostart", headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const req = request(
      {
        host: "127.0.0.1",
        port,
        path,
        method,
        headers: data
          ? { ...headers, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) }
          : headers,
      },
      (res) => {
        let resBody = "";
        res.on("data", (c) => (resBody += c));
        res.on("end", () => resolve({ status: res.statusCode, body: resBody }));
      }
    );
    req.on("error", reject);
    req.end(data ?? undefined);
  });
}

async function withAutostartServer(fn) {
  const port = asPortSeq++;
  const origin = `http://127.0.0.1:${port}`;
  const fake = fakeAutostartOps();
  const server5 = createHelmServer({ port, allowedOrigin: origin, token, autostartOps: fake.ops });
  const call5 = (opts) => asRequest(port, opts);
  const headers5 = (overrides = {}) => ({ Host: `127.0.0.1:${port}`, Origin: origin, Authorization: `Bearer ${token}`, ...overrides });
  try {
    await fn({ ...fake, call: call5, headers: headers5, port });
  } finally {
    await new Promise((resolve) => server5.close(resolve));
  }
}

test("autostart: POST installs only through Host+Origin+Bearer, and reports the re-read state", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const res = await call({ method: "POST", headers: headers(), body: { autostart: true } });
    assert.equal(res.status, 200);
    assert.deepEqual(calls, ["install"]);
    assert.equal(JSON.parse(res.body).autostart.installed, true);

    const off = await call({ method: "POST", headers: headers(), body: { autostart: false } });
    assert.equal(off.status, 200);
    assert.deepEqual(calls, ["install", "uninstall"]);
    assert.equal(JSON.parse(off.body).autostart.installed, false, "revoke must actually remove the entry");
  });
});

test("autostart: GET reports state and installs NOTHING (no side effects on GET)", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const res = await call({ headers: headers() });
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    assert.equal(body.autostart.installed, false);
    assert.equal(body.autostart.supported, true);
    assert.deepEqual(calls, [], "a GET must never write a persistence entry");
  });
});

test("autostart: negative — cross-origin POST is rejected AND nothing is installed", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const res = await call({ method: "POST", headers: headers({ Origin: "https://evil.example" }), body: { autostart: true } });
    assert.equal(res.status, 403);
    assert.equal(JSON.parse(res.body).error, "origin_mismatch");
    assert.deepEqual(calls, [], "a rejected request must not have reached the installer");
  });
});

test("autostart: negative — the hosted detection origin gets no access to this route", async () => {
  await withAutostartServer(async ({ calls, call, port }) => {
    // /version and /pair/challenge answer this origin with no token at all.
    // This route must not have joined that carve-out.
    const res = await call({ method: "POST", headers: { Host: `127.0.0.1:${port}`, Origin: DETECTION_ORIGIN }, body: { autostart: true } });
    assert.equal(res.status, 403);
    assert.equal(JSON.parse(res.body).error, "origin_mismatch");
    assert.deepEqual(calls, []);
  });
});

test("autostart: negative — mismatched Host (DNS rebinding) is rejected AND nothing is installed", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const res = await call({ method: "POST", headers: headers({ Host: "helm.evil.example" }), body: { autostart: true } });
    assert.equal(res.status, 403);
    assert.equal(JSON.parse(res.body).error, "host_mismatch");
    assert.deepEqual(calls, []);
  });
});

test("autostart: negative — no bearer token is rejected AND nothing is installed", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const noAuth = headers();
    delete noAuth.Authorization;
    const res = await call({ method: "POST", headers: noAuth, body: { autostart: true } });
    assert.equal(res.status, 401);
    assert.equal(JSON.parse(res.body).error, "unauthorized");
    assert.deepEqual(calls, []);

    const read = await call({ headers: noAuth });
    assert.equal(read.status, 401, "not in the pre-auth static allowlist either");
  });
});

test("autostart: negative — a body naming neither toggle is a 400, not a silent no-op", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const res = await call({ method: "POST", headers: headers(), body: { enabled: "yes" } });
    assert.equal(res.status, 400);
    assert.equal(JSON.parse(res.body).error, "missing_autostart_or_shortcut");
    assert.deepEqual(calls, []);
  });
});

test("autostart: shortcut toggles through the same gate, independently of autostart", async () => {
  await withAutostartServer(async ({ calls, call, headers }) => {
    const res = await call({ method: "POST", headers: headers(), body: { shortcut: true } });
    assert.equal(res.status, 200);
    assert.deepEqual(calls, ["installShortcut"]);
    assert.equal(JSON.parse(res.body).shortcut.installed, true);
    assert.equal(JSON.parse(res.body).autostart.installed, false, "the two toggles are not wired together");
  });
});

// --- HELM-BIND-WIRE-1: connector/action dispatch is gated by caller origin ---
//
// No shipped pack has a "connectors"/"actions" step yet (compile-packs.mjs:101
// hardcodes connectors: []; that's HELM-BIND-4's, not this row's). So
// __setManifestOverrideForTest (run-actions.mjs) stands in for a compiled
// pack: the REAL server.mjs POST /run/start route and the REAL mcp.mjs
// POST /mcp handler both run completely unmodified — only which manifest a
// workflow_id resolves to is swapped, for one test-only id, for the
// duration of this block. An "actions" step (action_id/type/target_host) is
// used, not a bare "connectors" one — dispatch.mjs's own tests establish
// that a bare connectors item has no target_host to build a request from and
// always fails loud regardless of wiring (HELM-BIND-3's documented gap).
const WIRE_WORKFLOW_ID = "helm-bind-wire-1-test-fixture";
const WIRE_CREDENTIAL_REF = "vault://helm/connectors/http/example/credential"; // http-send.contract.json's vault_scope[0]

function wireTestManifest() {
  return {
    manifest_version: "1",
    workflow_id: WIRE_WORKFLOW_ID,
    trigger: { type: "manual" },
    connectors: [],
    nodes: [],
    gates: [],
    actions: [{ action_id: "a1", type: "http.send", target_host: "api.example.com" }],
  };
}

async function withRunEngineServer(fn) {
  const port = asPortSeq++;
  const origin = `http://127.0.0.1:${port}`;
  const dbDir = mkdtempSync(join(tmpdir(), "helm-bind-wire-test-"));
  const db = openJournal(join(dbDir, "journal.db"));
  const server6 = createHelmServer({ port, allowedOrigin: origin, token, db });
  const call6 = (opts) => asRequest(port, opts);
  const headers6 = (overrides = {}) => ({ Host: `127.0.0.1:${port}`, Origin: origin, Authorization: `Bearer ${token}`, ...overrides });
  vaultSet(WIRE_CREDENTIAL_REF, { access_token: "tok-wire-1" });
  __setHostResolverForTest(async (hostname) => {
    if (hostname === "api.example.com") return ["93.184.216.34"];
    throw new Error(`test resolver: unexpected hostname ${hostname}`);
  });
  __setManifestOverrideForTest((workflowId) => (workflowId === WIRE_WORKFLOW_ID ? wireTestManifest() : null));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(new URL(url).host, "api.example.com", "connector dispatch must reach the contract-allowlisted host, nothing else");
    return new Response(Buffer.from('{"ok":true}'), { status: 200 });
  };
  try {
    await fn({ call: call6, headers: headers6, port, db });
  } finally {
    globalThis.fetch = originalFetch;
    __setHostResolverForTest(null);
    __setManifestOverrideForTest(null);
    await new Promise((resolve) => server6.close(resolve));
    db.close();
    rmSync(dbDir, { recursive: true, force: true });
  }
}

// Polls the in-process event bus (which replays the last event to a late
// subscriber — event-bus.mjs's lastEventByRun) for a terminal state, up to
// ~1s. Works for both outcomes here: a "completed" run has one, and so does
// a "failed" one — startWorkflowRun's own .catch() always publishes one of
// the two, even though a mid-run throw never updates the `runs` table's
// state column (that gap predates this row and is not in its fence).
async function waitForRunEvent(runId) {
  for (let i = 0; i < 40; i++) {
    let seen = null;
    const unsubscribe = subscribeRunEvents(runId, (data) => { seen = data; });
    unsubscribe();
    if (seen && (seen.state === "completed" || seen.state === "failed")) return seen;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`run ${runId} never reached a terminal event`);
}

test("HELM-BIND-WIRE-1 POSITIVE: POST /run/start (the UI/human path) dispatches an actions step to http.send and attests it", async () => {
  await withRunEngineServer(async ({ call, headers, db }) => {
    const res = await call({ method: "POST", path: "/run/start", headers: headers(), body: { workflow_id: WIRE_WORKFLOW_ID } });
    assert.equal(res.status, 200);
    const runId = JSON.parse(res.body).run_id;

    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "completed", `UI-initiated run with an actions step must complete, got: ${JSON.stringify(event)}`);

    const row = db.prepare("SELECT output_json FROM step_results WHERE run_id = ? AND step_id = ?").get(runId, "actions:a1");
    assert.ok(row, "the actions:a1 step must have actually run and memoized an output");
    const output = JSON.parse(row.output_json);
    const attestation = output.attestation;
    assert.equal(attestation.connector_id, "http.send");
    assert.equal(attestation.endpoint_host, "api.example.com");
    assert.ok(attestation.payload_digest.startsWith("sha256:"));
    // quoted proof for the check-off:
    console.log("HELM-BIND-WIRE-1 UI-path connector_attestation:", JSON.stringify(attestation));
  });
});

test("HELM-BIND-WIRE-1 NEGATIVE: POST /mcp tools/call workflow.run (the MCP/agent path) on the SAME manifest does NOT dispatch the actions step", async () => {
  await withRunEngineServer(async ({ call, headers, db }) => {
    const rpcBody = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "workflow.run",
        arguments: { workflow_id: WIRE_WORKFLOW_ID },
        _meta: {
          "io.modelcontextprotocol/protocolVersion": "2026-07-28",
          "io.modelcontextprotocol/clientInfo": { name: "helm-bind-wire-1-test", version: "1.0.0" },
          "io.modelcontextprotocol/clientCapabilities": { extensions: { "io.modelcontextprotocol/tasks": {} } },
        },
      },
    };
    const mcpHeaders = headers({ "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "workflow.run" });
    const res = await call({ method: "POST", path: "/mcp", headers: mcpHeaders, body: rpcBody });
    assert.equal(res.status, 200);
    const body = JSON.parse(res.body);
    const runId = body.result.task.taskId;

    const event = await waitForRunEvent(runId);
    assert.equal(event.state, "failed", `MCP-initiated run with an actions step must FAIL, never complete, got: ${JSON.stringify(event)}`);
    assert.match(
      event.error,
      /no runner configured for step kind "actions"/,
      "the failure must be the unwired-otherKindsRunner throw, not something unrelated"
    );

    const row = db.prepare("SELECT 1 FROM step_results WHERE run_id = ? AND step_id = ?").get(runId, "actions:a1");
    assert.equal(row, undefined, "the actions:a1 step must never have run — no memoized output at all");
    // quoted proof for the check-off:
    console.log("HELM-BIND-WIRE-1 MCP request:", JSON.stringify(rpcBody), "-> response:", res.body, "-> terminal event:", JSON.stringify(event));
  });
});

// SIGN-SEAM-1 / SIGNING-SURFACES-BUILD-SPEC.md §3, phil condition #5: the
// signer-command config change is consent-gated at the same tier as
// pairing/token changes — a ticket must be minted by a dedicated route
// (mirroring POST /evidence/export/ticket) before POST /signer/config will
// accept a write. These tests exercise the HTTP contract only; the deeper
// hardening (argv-array spawn, empty env, verify-after-sign, etc.) is
// covered by hub/signer-exec.test.mjs.
function signerConfigBody() {
  const { publicKey } = generateKeyPairSync("ed25519");
  return {
    command: "/usr/local/bin/my-signer",
    args: ["--slot", "1"],
    algo: "ed25519",
    publicKeyDerBase64: publicKey.export({ format: "der", type: "spki" }).toString("base64"),
  };
}

test("GET /signer/config returns null before anything is configured", async () => {
  const res = await get("/signer/config", headers());
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { config: null });
});

test("POST /signer/config without a ticket is refused — consent_required", async () => {
  const res = await post("/signer/config", { config: signerConfigBody() }, headers());
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body).error, "consent_required");
});

test("POST /signer/config with a bogus ticket is refused", async () => {
  const res = await post("/signer/config", { ticket: "not-a-real-ticket", config: signerConfigBody() }, headers());
  assert.equal(res.status, 403);
  assert.equal(JSON.parse(res.body).error, "consent_required");
});

test("POST /signer/config succeeds with a ticket minted via POST /signer/config/ticket, and the ticket is single-use", async () => {
  const ticketRes = await post("/signer/config/ticket", {}, headers());
  assert.equal(ticketRes.status, 200);
  const { ticket } = JSON.parse(ticketRes.body);
  assert.ok(ticket && ticket.length > 0);

  const body = signerConfigBody();
  const writeRes = await post("/signer/config", { ticket, config: body }, headers());
  assert.equal(writeRes.status, 200);
  const written = JSON.parse(writeRes.body).config;
  assert.equal(written.command, "/usr/local/bin/my-signer");

  const getRes = await get("/signer/config", headers());
  assert.equal(JSON.parse(getRes.body).config.command, "/usr/local/bin/my-signer");

  // Single-use — the SAME ticket must not work a second time (P3-D9 shape,
  // same discipline as pairing nonces / stream / export tickets).
  const replay = await post("/signer/config", { ticket, config: body }, headers());
  assert.equal(replay.status, 403);
  assert.equal(JSON.parse(replay.body).error, "consent_required");
});

test("POST /signer/config rejects a malformed config even with a valid ticket", async () => {
  const ticketRes = await post("/signer/config/ticket", {}, headers());
  const { ticket } = JSON.parse(ticketRes.body);
  const badBody = signerConfigBody();
  badBody.args = "--slot 1"; // string, not argv array — must be rejected
  const res = await post("/signer/config", { ticket, config: badBody }, headers());
  assert.equal(res.status, 400);
  assert.equal(JSON.parse(res.body).error, "invalid_signer_config");
});

test("POST /signer/config/ticket is not registered as an MCP tool — an MCP tools/call cannot mint a consent ticket", async () => {
  await withRunEngineServer(async ({ call, headers: headers6 }) => {
    const rpcBody = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
    const res = await call({ method: "POST", path: "/mcp", headers: headers6(), body: rpcBody });
    assert.equal(res.status, 200);
    const names = JSON.parse(res.body).result.tools.map((t) => t.name);
    assert.ok(!names.includes("signer.config"), "no signer.config MCP tool should exist — the consent ticket route is UI-only");
    assert.ok(!names.some((n) => n.startsWith("signer.")), "no signer.* MCP tool should exist at all");
  });
});
