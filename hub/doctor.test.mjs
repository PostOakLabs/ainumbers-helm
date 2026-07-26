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

function anchorCheck(report) {
  return report.checks.find((c) => c.name === "anchor_on_checkpoint");
}

test("doctor: all checks pass on a fresh state dir, port reported free", async () => {
  const report = await runDoctor();
  assert.equal(report.ok, true, JSON.stringify(report.checks));
  assert.match(portCheck(report).detail, /free/);
});

// HELM-ANCHOR-DEFAULT-FLIP-1: the default (anchorOnCheckpoint unset ⇒ false)
// must be VISIBLE here even though it isn't a doctor FAILURE — an unanchored
// checkpoint is a fully valid, supported config, not a broken one (same
// informational shape as version_check_notice below). This is one of the
// row's two required visibility surfaces; the other is the boot-log warn in
// index.mjs.
test("doctor: reports checkpoints unanchored, and how to enable, when anchorOnCheckpoint is off (the default)", async () => {
  const report = await runDoctor();
  const check = anchorCheck(report);
  assert.ok(check, "anchor_on_checkpoint check must be present");
  assert.equal(check.pass, true, "unanchored is a valid config, must not fail doctor overall");
  assert.match(check.detail, /NOT anchored/);
  assert.match(check.detail, /anchorOnCheckpoint.*true/);
});

test("doctor: reports the active relay/CA when anchoring is enabled", async () => {
  writeFileSync(
    join(TMP, "config.json"),
    JSON.stringify({ port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "", anchorOnCheckpoint: true, relayBase: "https://freetsa.org", ca: "freetsa" })
  );
  const report = await runDoctor();
  const check = anchorCheck(report);
  assert.equal(check.pass, true);
  assert.match(check.detail, /freetsa\.org\/relay\/freetsa/);
  writeFileSync(join(TMP, "config.json"), JSON.stringify({ port: PORT, allowedOrigin: ORIGIN, versionCheckUrl: "" }));
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
