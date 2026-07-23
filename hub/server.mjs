// Loopback REST + SSE server. D8 hardening, in order, on every request:
//   1. Host header must exactly equal 127.0.0.1:<port>        (DNS-rebinding defense)
//   2. Origin header must exactly equal the configured origin  (no wildcard CORS)
//   3. Authorization: Bearer <token> must match                (pairing token)
// GET handlers are read-only by construction — no side effects on GET.
import { createServer } from "node:http";
import { tokenMatches } from "./token.mjs";
import { log } from "./log.mjs";

const START = Date.now();

function checkHost(req, port) {
  return req.headers.host === `127.0.0.1:${port}`;
}

function checkOrigin(req, allowedOrigin) {
  return req.headers.origin === allowedOrigin;
}

function applyCors(res, allowedOrigin) {
  res.setHeader("Access-Control-Allow-Origin", allowedOrigin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
}

function deny(res, status, error) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error }));
}

function handleHealth(req, res) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ status: "ok", uptimeMs: Date.now() - START }));
}

function handleEvents(req, res) {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.write(`event: ready\ndata: {}\n\n`);
  const heartbeat = setInterval(() => res.write(`event: heartbeat\ndata: {}\n\n`), 15000);
  req.on("close", () => clearInterval(heartbeat));
}

const ROUTES = {
  "GET /health": handleHealth,
  "GET /events": handleEvents,
};

export function createHelmServer({ port, allowedOrigin, token }) {
  const server = createServer((req, res) => {
    if (!checkHost(req, port)) {
      log.warn("rejected: host mismatch", { host: req.headers.host, path: req.url });
      return deny(res, 403, "host_mismatch");
    }
    if (!checkOrigin(req, allowedOrigin)) {
      log.warn("rejected: origin mismatch", { origin: req.headers.origin, path: req.url });
      return deny(res, 403, "origin_mismatch");
    }
    applyCors(res, allowedOrigin);

    if (req.method === "OPTIONS") {
      // Preflight: browsers never send Authorization on OPTIONS. Host+Origin
      // checks above already gate this; the real request still needs a token.
      res.writeHead(204);
      return res.end();
    }

    const auth = req.headers.authorization || "";
    const presented = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!tokenMatches(token, presented)) {
      log.warn("rejected: bad or missing token", { path: req.url });
      return deny(res, 401, "unauthorized");
    }

    const key = `${req.method} ${new URL(req.url, `http://x`).pathname}`;
    const handler = ROUTES[key];
    if (!handler) return deny(res, 404, "not_found");
    handler(req, res);
  });
  server.listen(port, "127.0.0.1");
  return server;
}
