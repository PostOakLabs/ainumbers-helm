// Connector 4 (HELM-P2-H9b): smtp.send — pure-config outbound email over
// raw SMTP (node:net/node:tls, zero dependency — D11). There is no HTTP
// fetch here to route through connector.mjs's performEgress, so this module
// re-derives the SAME guarded-egress decision sequence by hand, in the same
// order, before ever opening a socket:
//   1. contract allowlist check (assertEgressAllowed)
//   2. DNS-resolved-IP deny-list check (resolveVettedIp — the exact
//      function H9a's HTTP path uses, so the rebinding guard is shared,
//      not reimplemented) — then pinHostResolution pins the SAME vetted IP
//      for the socket connect below, so the check and the connect can never
//      resolve to different addresses (HELM-P2-R11-F1 DNS-rebinding fix).
//   3. recordEgress — a blocked target is journaled BEFORE any TCP connect
//      is attempted, matching every other connector's transcript shape.
//
// STARTTLS negotiated opportunistically (secure:"starttls", the default) or
// required (secure:"tls", implicit TLS on connect) or refused (secure:
// "none", for local/test relays only). AUTH LOGIN only — the one mechanism
// every mainstream SMTP relay accepts; base64 is *encoding* not *secrecy*,
// so plaintext AUTH LOGIN over an unencrypted channel is refused unless the
// caller explicitly set secure:"none".
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createHash } from "node:crypto";
import { assertEgressAllowed, resolveVettedIp, pinHostResolution, recordEgress, buildConnectorAttestation } from "../connector.mjs";
import { vaultGet } from "../vault.mjs";

export const CONNECTOR_ID = "smtp.send";
export const CONNECTOR_VERSION = "1.0.0";

const SMTP_TIMEOUT_MS = 15 * 1000; // HELM-SEC-5 doctrine: a hung relay must not stall the runtime forever

function sha256ref(buf) {
  return `sha256:${createHash("sha256").update(buf).digest("hex")}`;
}

// Line-buffered SMTP reply reader. A multi-line reply (e.g. EHLO's
// capability list) shares one status code across lines, distinguished by
// '-' (more lines coming) vs ' ' (final line) at column 4 (RFC 5321 §4.2).
function makeReader(socket) {
  let buf = "";
  const waiters = [];
  let pending = null;

  function pushLine(line) {
    if (!pending) pending = { code: null, lines: [] };
    pending.lines.push(line);
    if (line.charAt(3) !== "-") {
      pending.code = line.slice(0, 3);
      const done = pending;
      pending = null;
      const w = waiters.shift();
      if (w) w.resolve(done);
    }
  }

  socket.on("data", (chunk) => {
    buf += chunk.toString("utf8");
    let idx;
    while ((idx = buf.indexOf("\r\n")) !== -1) {
      pushLine(buf.slice(0, idx));
      buf = buf.slice(idx + 2);
    }
  });

  return {
    readResponse() {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("smtp.send: response timeout")), SMTP_TIMEOUT_MS);
        waiters.push({ resolve: (v) => { clearTimeout(timer); resolve(v); } });
      });
    },
  };
}

function writeLine(socket, line) {
  socket.write(line + "\r\n");
}

async function expect(reader, okCodes) {
  const res = await reader.readResponse();
  if (!okCodes.includes(res.code)) {
    throw new Error(`smtp.send: unexpected response ${res.code}: ${res.lines.join(" | ")}`);
  }
  return res;
}

function defaultOpenSocket(host, port, secure) {
  return new Promise((resolve, reject) => {
    const opts = { host, port };
    const socket = secure ? tlsConnect({ ...opts, servername: host }, () => resolve(socket)) : netConnect(opts, () => resolve(socket));
    socket.setTimeout(SMTP_TIMEOUT_MS, () => {
      socket.destroy();
      reject(new Error("smtp.send: connection timeout"));
    });
    socket.once("error", reject);
  });
}

// Overridable only for tests — real DNS/TCP to a public-looking hostname
// isn't reachable in the sandboxed test runner, and the mock relay must
// bind to loopback while assertResolvedIpAllowed's hostname check (already
// proven by connector.test.mjs/http-send.test.mjs) needs a non-literal
// hostname to exercise the resolver-override path rather than the
// immediate literal-IP deny. Production always uses the real connect.
let openSocket = defaultOpenSocket;
export function __setSocketConnectForTest(fn) {
  openSocket = fn ?? defaultOpenSocket;
}

function defaultUpgradeToTls(socket, servername) {
  return new Promise((resolve, reject) => {
    const upgraded = tlsConnect({ socket, servername }, () => resolve(upgraded));
    upgraded.once("error", reject);
  });
}

// Overridable only for tests — a real STARTTLS handshake needs a genuine TLS
// server; this lets a test assert the servername argument (the actual
// security property of HELM-P2-R11-F2) without standing up a cert harness.
let upgradeToTls = defaultUpgradeToTls;
export function __setTlsUpgradeForTest(fn) {
  upgradeToTls = fn ?? defaultUpgradeToTls;
}

// Runs the full EHLO -> [STARTTLS] -> [AUTH] -> MAIL/RCPT/DATA dialogue.
// Returns the raw message bytes actually sent, for the attestation digest.
async function runDialogue(socket, { host, heloHost, from, to, subject, text, authUser, authPass, secure }) {
  let activeSocket = socket;
  let activeReader = makeReader(socket);
  await expect(activeReader, ["220"]);

  writeLine(activeSocket, `EHLO ${heloHost}`);
  let ehlo = await expect(activeReader, ["250"]);
  let caps = ehlo.lines.map((l) => l.slice(4).toUpperCase());
  let isSecure = secure === "tls";

  if (!isSecure && secure === "starttls") {
    if (!caps.some((c) => c.startsWith("STARTTLS"))) {
      throw new Error("smtp.send: server does not offer STARTTLS (secure:\"starttls\" requires it — use \"none\" only for trusted local relays)");
    }
    writeLine(activeSocket, "STARTTLS");
    await expect(activeReader, ["220"]);
    activeSocket = await upgradeToTls(activeSocket, host);
    activeReader = makeReader(activeSocket);
    writeLine(activeSocket, `EHLO ${heloHost}`);
    ehlo = await expect(activeReader, ["250"]);
    caps = ehlo.lines.map((l) => l.slice(4).toUpperCase());
    isSecure = true;
  }

  if (authUser) {
    if (!isSecure) {
      throw new Error("smtp.send: refusing AUTH LOGIN over an unencrypted channel (secure:\"none\")");
    }
    writeLine(activeSocket, "AUTH LOGIN");
    await expect(activeReader, ["334"]);
    writeLine(activeSocket, Buffer.from(authUser, "utf8").toString("base64"));
    await expect(activeReader, ["334"]);
    writeLine(activeSocket, Buffer.from(authPass, "utf8").toString("base64"));
    await expect(activeReader, ["235"]);
  }

  writeLine(activeSocket, `MAIL FROM:<${from}>`);
  await expect(activeReader, ["250"]);
  for (const rcpt of to) {
    writeLine(activeSocket, `RCPT TO:<${rcpt}>`);
    await expect(activeReader, ["250", "251"]);
  }
  writeLine(activeSocket, "DATA");
  await expect(activeReader, ["354"]);

  const header = [`From: ${from}`, `To: ${to.join(", ")}`, `Subject: ${subject}`, `Date: ${new Date().toUTCString()}`, ""].join("\r\n");
  const body = `${header}${text}`.replace(/\r\n\./g, "\r\n.."); // dot-stuffing (RFC 5321 §4.5.2)
  activeSocket.write(`${body}\r\n.\r\n`);
  await expect(activeReader, ["250"]);

  writeLine(activeSocket, "QUIT");
  try {
    await expect(activeReader, ["221"]);
  } catch {
    // best-effort — the message is already accepted at this point
  }
  activeSocket.end();
  if (activeSocket !== socket) socket.destroy();

  return Buffer.from(body, "utf8");
}

export function createSmtpConnector({ db, contract, contractDigest }) {
  let vaultSlice = null;

  return {
    connectorId: CONNECTOR_ID,

    async init(scopedVaultSlice) {
      vaultSlice = scopedVaultSlice;
    },

    async selfTest() {
      return { ok: true };
    },

    // payload: { host, port, secure? ("starttls" default | "tls" | "none"),
    //   from, to: [...], subject, text, runId, workflowManifestDigest, classification? }
    async send({ host, port, secure = "starttls", from, to, subject, text, runId, workflowManifestDigest, classification }) {
      const hostPort = `${host}:${port}`;
      const requestDigest = sha256ref(Buffer.from(JSON.stringify({ host: hostPort, from, to, subject }), "utf8"));

      if (!assertEgressAllowed(contract, { host: hostPort, method: "SEND" })) {
        recordEgress(db, { connectorId: CONNECTOR_ID, destinationHost: hostPort, operation: "SEND", decision: "blocked", requestDigest });
        throw new Error(`egress blocked: ${CONNECTOR_ID} -> SEND ${hostPort} not in contract allowlist`);
      }
      let vettedIp;
      try {
        vettedIp = await resolveVettedIp(host);
      } catch (err) {
        recordEgress(db, { connectorId: CONNECTOR_ID, destinationHost: hostPort, operation: "SEND", decision: "blocked", requestDigest });
        throw err;
      }

      let authUser = null;
      let authPass = null;
      if (vaultSlice?.credentialRef) {
        const cred = vaultGet(vaultSlice.credentialRef);
        if (cred) {
          authUser = cred.username ?? cred.user ?? null;
          authPass = cred.password ?? cred.pass ?? null;
        }
      }

      const unpin = pinHostResolution(host, vettedIp);
      let socket;
      try {
        socket = await openSocket(host, port, secure === "tls");
      } finally {
        unpin();
      }
      const messageBytes = await runDialogue(socket, { host, heloHost: "helm.local", from, to, subject, text, authUser, authPass, secure });

      const responseDigest = sha256ref(messageBytes);
      recordEgress(db, { connectorId: CONNECTOR_ID, destinationHost: hostPort, operation: "SEND", decision: "allowed", requestDigest, responseDigest });

      const attestation = buildConnectorAttestation({
        runId,
        workflowManifestDigest,
        connectorId: CONNECTOR_ID,
        connectorVersion: CONNECTOR_VERSION,
        contractDigest,
        operation: "smtp.send",
        scope: contract.scopes,
        endpointHost: hostPort,
        payloadBytes: messageBytes,
        classification,
      });

      return { attestation };
    },

    async dispose() {
      vaultSlice = null;
    },
  };
}
