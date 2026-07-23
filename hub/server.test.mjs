import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:http";

const TMP = mkdtempSync(join(tmpdir(), "helm-test-"));
process.env.HELM_HOME = TMP;

const PORT = 41999;
const ORIGIN = "null";

writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN }));

const { loadConfig } = await import("./config.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { createHelmServer, MAX_SSE_CONNECTIONS } = await import("./server.mjs");

const config = loadConfig();
const token = loadOrCreateToken();
let server;

before(() => {
  server = createHelmServer({ port: config.port, allowedOrigin: config.allowedOrigin, token });
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
