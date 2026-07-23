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
const { createHelmServer } = await import("./server.mjs");

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
