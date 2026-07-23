// Mock relay only speaks plaintext (secure:"none") — TLS/STARTTLS negotiation
// and AUTH LOGIN are exercised by code inspection + the shared
// assertResolvedIpAllowed/recordEgress paths already proven by
// http-send.test.mjs and google-drive-fetch.test.mjs; standing up a TLS mock
// relay for this MVP would add a self-signed-cert harness with no additional
// egress-guard coverage (the guard runs identically before secure:"tls").
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer, connect as netConnect } from "node:net";
import { validate } from "../../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const TMP = mkdtempSync(join(tmpdir(), "helm-smtp-send-test-"));
process.env.HELM_HOME = TMP;

const { openJournal } = await import("../journal.mjs");
const { loadContract, __setHostResolverForTest } = await import("../connector.mjs");
const { createSmtpConnector, CONNECTOR_ID, __setSocketConnectForTest, __setTlsUpgradeForTest } = await import("./smtp-send.mjs");

// "mock-smtp.test" is a non-literal hostname so assertResolvedIpAllowed
// takes the resolver-override path (proven safe by connector.test.mjs);
// 127.0.0.1 itself is in the private/link-local deny list by design (H9a)
// and would be rejected before any resolver is even consulted.
__setHostResolverForTest(async (hostname) => {
  if (hostname === "mock-smtp.test") return ["203.0.113.5"]; // TEST-NET-3, RFC 5737 — not deny-listed, never routable
  throw new Error(`test resolver: unexpected hostname ${hostname}`);
});
process.on("exit", () => __setHostResolverForTest(null));

const ATTESTATION_SCHEMA = JSON.parse(
  readFileSync(join(HERE, "..", "..", "schema", "objects", "connector_attestation.schema.json"), "utf8")
);

// Minimal plaintext SMTP dialogue: no STARTTLS advertised (so secure:"none"
// callers proceed unauthenticated), accepts exactly one message.
function startMockRelay({ starttls = false } = {}) {
  return new Promise((resolve) => {
    let received = null;
    const server = createServer((socket) => {
      socket.write("220 mock ESMTP\r\n");
      let buf = "";
      let inData = false;
      let dataBuf = "";
      socket.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        let idx;
        while ((idx = buf.indexOf("\r\n")) !== -1) {
          const line = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          if (inData) {
            if (line === ".") {
              inData = false;
              received = dataBuf;
              socket.write("250 Message accepted\r\n");
            } else {
              dataBuf += (dataBuf ? "\r\n" : "") + line;
            }
            continue;
          }
          if (line.startsWith("EHLO")) {
            socket.write(starttls ? "250-mock\r\n250 STARTTLS\r\n" : "250 mock\r\n");
          } else if (line === "STARTTLS" && starttls) {
            socket.write("220 Go ahead\r\n");
          } else if (line.startsWith("MAIL FROM")) socket.write("250 OK\r\n");
          else if (line.startsWith("RCPT TO")) socket.write("250 OK\r\n");
          else if (line === "DATA") {
            inData = true;
            dataBuf = "";
            socket.write("354 End with .\r\n");
          } else if (line === "QUIT") {
            socket.write("221 Bye\r\n");
            socket.end();
          }
        }
      });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, getReceived: () => received }));
  });
}

test("smtp.send: happy path over a plaintext mock relay produces a schema-valid attestation", async () => {
  const { server, port, getReceived } = await startMockRelay();
  __setSocketConnectForTest((host, connectPort) => new Promise((resolve, reject) => {
    assert.equal(host, "mock-smtp.test");
    assert.equal(connectPort, port);
    const socket = netConnect({ host: "127.0.0.1", port }, () => resolve(socket));
    socket.once("error", reject);
  }));
  try {
    const db = openJournal(join(TMP, "smtp-ok.db"));
    const { contract, contractDigest } = loadContract(join(HERE, "smtp-send.contract.json"));
    const tampered = { ...contract, allowed_hosts: [`mock-smtp.test:${port}`] };

    const connector = createSmtpConnector({ db, contract: tampered, contractDigest });
    await connector.init({});
    assert.deepEqual(await connector.selfTest(), { ok: true });

    const { attestation } = await connector.send({
      host: "mock-smtp.test", port, secure: "none",
      from: "helm@example.com", to: ["ops@example.com"], subject: "test",
      text: "hello from smtp.send", runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
    });

    assert.match(getReceived(), /hello from smtp\.send/);
    assert.equal(attestation.connector_id, CONNECTOR_ID);
    assert.equal(attestation.endpoint_host, `mock-smtp.test:${port}`);
    const errs = validate(ATTESTATION_SCHEMA, attestation);
    assert.deepEqual(errs, []);

    const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all(`egress:${CONNECTOR_ID}`);
    assert.equal(rows.length, 1);
    assert.equal(JSON.parse(rows[0].entry_json).decision, "allowed");

    await connector.dispose();
    db.close();
  } finally {
    __setSocketConnectForTest(null);
    server.close();
  }
});

test("smtp.send: STARTTLS upgrade validates the cert against the relay host, not the EHLO identity (HELM-P2-R11-F2)", async () => {
  const { server, port, getReceived } = await startMockRelay({ starttls: true });
  __setSocketConnectForTest((host, connectPort) => new Promise((resolve, reject) => {
    const socket = netConnect({ host: "127.0.0.1", port }, () => resolve(socket));
    socket.once("error", reject);
  }));
  let tlsUpgradeServername = null;
  __setTlsUpgradeForTest((socket, servername) => {
    tlsUpgradeServername = servername;
    return Promise.resolve(socket); // stand-in: no real cert to validate here — asserting the servername argument is the fix under test
  });
  try {
    const db = openJournal(join(TMP, "smtp-starttls.db"));
    const { contract, contractDigest } = loadContract(join(HERE, "smtp-send.contract.json"));
    const tampered = { ...contract, allowed_hosts: [`mock-smtp.test:${port}`] };

    const connector = createSmtpConnector({ db, contract: tampered, contractDigest });
    await connector.init({});

    await connector.send({
      host: "mock-smtp.test", port, secure: "starttls",
      from: "helm@example.com", to: ["ops@example.com"], subject: "test",
      text: "hello over starttls", runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
    });

    assert.equal(tlsUpgradeServername, "mock-smtp.test");
    assert.notEqual(tlsUpgradeServername, "helm.local");
    assert.match(getReceived(), /hello over starttls/);

    await connector.dispose();
    db.close();
  } finally {
    __setSocketConnectForTest(null);
    __setTlsUpgradeForTest(null);
    server.close();
  }
});

test("smtp.send: a host outside the contract's allowlist is blocked + transcript-logged, no socket ever opens", async () => {
  const db = openJournal(join(TMP, "smtp-blocked.db"));
  const { contract, contractDigest } = loadContract(join(HERE, "smtp-send.contract.json"));

  const connector = createSmtpConnector({ db, contract, contractDigest });
  await connector.init({});

  await assert.rejects(
    () => connector.send({
      host: "not-allowed.example", port: 587, secure: "none",
      from: "a@example.com", to: ["b@example.com"], subject: "x", text: "x",
      runId: "run-1", workflowManifestDigest: "sha256:" + "a".repeat(64),
    }),
    /egress blocked/
  );

  const rows = db.prepare("SELECT * FROM journal WHERE stream_id = ?").all(`egress:${CONNECTOR_ID}`);
  assert.equal(rows.length, 1);
  assert.equal(JSON.parse(rows[0].entry_json).decision, "blocked");
  db.close();
});

process.on("exit", () => rmSync(TMP, { recursive: true, force: true }));
