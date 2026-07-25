import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTcpServer } from "node:net";

const TMP = mkdtempSync(join(tmpdir(), "helm-doctor-test-"));
process.env.HELM_HOME = TMP;

// Pin a port of our own rather than inheriting the 4173 default: these tests
// bind it for real, and a developer running helmd while running the suite
// would otherwise hit a confusing collision. versionCheckUrl is disabled so
// the suite never depends on the network.
const PORT = 41777;
const ORIGIN = `http://127.0.0.1:${PORT}`;
writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "" }));

const { runDoctor } = await import("./doctor.mjs");
const { createHelmServer } = await import("./server.mjs");
const { loadOrCreateToken } = await import("./token.mjs");
const { loadOrCreateKeys } = await import("./keys.mjs");

after(() => rmSync(TMP, { recursive: true, force: true }));

function listen(server, port) {
  return new Promise((resolve) => server.listen(port, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function portCheck(report) {
  return report.checks.find((c) => c.name === "port_ok");
}

test("doctor: all checks pass on a fresh state dir, port reported free", async () => {
  const report = await runDoctor();
  assert.equal(report.ok, true, JSON.stringify(report.checks));
  assert.match(portCheck(report).detail, /free/);
});

// The regression this exists to prevent: the port check probed bindability,
// so the running daemon holding its own port made doctor FAIL. INSTALL.md
// points users at doctor as the post-install step, which meant the first
// thing a new user did reported FAIL on a perfectly healthy system.
test("doctor: passes while helmd itself is holding the port", async () => {
  const server = createHelmServer({
    port: PORT,
    allowedOrigin: ORIGIN,
    token: loadOrCreateToken(),
    identityKeys: loadOrCreateKeys(),
  });
  await listen(server, PORT);
  try {
    const report = await runDoctor();
    assert.equal(report.ok, true, JSON.stringify(report.checks));
    assert.match(portCheck(report).detail, /in use by helmd/);
  } finally {
    await close(server);
  }
});

// ...but a port held by something that is NOT helmd must still fail, or the
// fix above would have turned a real diagnostic into an unconditional pass.
test("doctor: fails when the port is held by a process that is not helmd", async () => {
  const squatter = createTcpServer(() => {});
  await listen(squatter, PORT);
  try {
    const report = await runDoctor();
    assert.equal(report.ok, false);
    assert.equal(portCheck(report).pass, false);
    assert.match(portCheck(report).detail, /in use by another process/);
  } finally {
    await close(squatter);
  }
});
