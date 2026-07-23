// Grep-gate (HELM-H5 acceptance): runs a real OAuth flow with a distinctive
// secret value, captures stdout/stderr + the full HELM_HOME tree, and proves
// the raw secret string never appears anywhere except inside the vault's own
// encrypted store (which is ciphertext, not plaintext).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readdirSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";

const TMP = mkdtempSync(join(tmpdir(), "helm-secretgate-test-"));
process.env.HELM_HOME = TMP;

const { startFlow, getFlowStatus } = await import("./oauth-pkce.mjs");
const { log } = await import("./log.mjs");

const SECRET_MARKER = `SECRET-MARKER-${randomBytes(16).toString("hex")}`;

function b64url(buf) {
  return buf.toString("base64url");
}

const codes = new Map();
const mockProvider = createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname === "/authorize") {
    const code = randomBytes(12).toString("hex");
    codes.set(code, url.searchParams.get("code_challenge"));
    const redirect = new URL(url.searchParams.get("redirect_uri"));
    redirect.searchParams.set("code", code);
    redirect.searchParams.set("state", url.searchParams.get("state"));
    res.writeHead(302, { Location: redirect.toString() });
    return res.end();
  }
  if (url.pathname === "/token" && req.method === "POST") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const params = new URLSearchParams(body);
      const challenge = codes.get(params.get("code"));
      const expected = b64url(createHash("sha256").update(params.get("code_verifier")).digest());
      if (expected !== challenge) {
        res.writeHead(400);
        return res.end("{}");
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: SECRET_MARKER, refresh_token: `refresh-${SECRET_MARKER}`, token_type: "Bearer", expires_in: 3600 }));
    });
    return;
  }
  res.writeHead(404);
  res.end();
});

let mockBase;
before(() => new Promise((resolve) => mockProvider.listen(0, "127.0.0.1", () => {
  mockBase = `http://127.0.0.1:${mockProvider.address().port}`;
  resolve();
})));

after(async () => {
  mockProvider.close();
  rmSync(TMP, { recursive: true, force: true });
});

function walk(dir) {
  let out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out = out.concat(walk(p));
    else out.push(p);
  }
  return out;
}

test("secret never appears in plaintext anywhere under HELM_HOME, only inside vault ciphertext", async () => {
  const capturedLogs = [];
  const originalWrite = { out: process.stdout.write.bind(process.stdout), err: process.stderr.write.bind(process.stderr) };
  process.stdout.write = (chunk, ...rest) => {
    capturedLogs.push(chunk.toString());
    return originalWrite.out(chunk, ...rest);
  };
  process.stderr.write = (chunk, ...rest) => {
    capturedLogs.push(chunk.toString());
    return originalWrite.err(chunk, ...rest);
  };

  try {
    const { flowId, authorizationUrl } = await startFlow({
      provider: "mock",
      authorizationEndpoint: `${mockBase}/authorize`,
      tokenEndpoint: `${mockBase}/token`,
      clientId: "test-client",
      scopes: ["read"],
    });
    await fetch(authorizationUrl);

    const start = Date.now();
    while (Date.now() - start < 2000) {
      if (getFlowStatus(flowId).status === "complete") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(getFlowStatus(flowId).status, "complete");
    log.info("gate check line mentioning nothing secret", { flowId });
  } finally {
    process.stdout.write = originalWrite.out;
    process.stderr.write = originalWrite.err;
  }

  for (const line of capturedLogs) {
    assert.doesNotMatch(line, new RegExp(SECRET_MARKER), `log output leaked the secret: ${line}`);
  }

  const vaultDir = join(TMP, "vault");
  for (const file of walk(TMP)) {
    if (statSync(file).size === 0) continue;
    const contents = readFileSync(file, "latin1"); // byte-preserving, safe for binary (sqlite) files too
    const inVault = file.startsWith(vaultDir);
    if (inVault) continue; // ciphertext tier — checked separately below for the literal marker
    assert.doesNotMatch(
      contents,
      new RegExp(SECRET_MARKER),
      `secret leaked in plaintext outside the vault: ${file}`
    );
  }

  // Even inside the vault directory (file-fallback tier only — native OS
  // keychains don't write to disk here at all), the value must be encrypted:
  // the literal marker must never appear, only its AES-GCM ciphertext.
  if (readdirSync(TMP).includes("vault")) {
    for (const file of readdirSync(vaultDir)) {
      const contents = readFileSync(join(vaultDir, file), "utf8");
      assert.doesNotMatch(contents, new RegExp(SECRET_MARKER), `vault file-fallback stored the secret in plaintext: ${file}`);
    }
  }
});
