import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildHandoffUrl,
  navigateToHandoff,
  probeDaemon,
  negotiateCapabilities,
  PROBE_STATE,
  UI_API_VERSIONS,
} from "./handoff.mjs";

test("buildHandoffUrl: default port, no pair nonce", () => {
  assert.equal(buildHandoffUrl("tok123"), "http://127.0.0.1:4173/#token=tok123");
});

test("buildHandoffUrl: custom port + pair nonce", () => {
  assert.equal(buildHandoffUrl("tok123", 5000, "nonceABC"), "http://127.0.0.1:5000/#token=tok123&pair=nonceABC");
});

test("buildHandoffUrl: throws without a token — never navigates blind", () => {
  assert.throws(() => buildHandoffUrl(""));
  assert.throws(() => buildHandoffUrl(null));
});

test("navigateToHandoff: performs a TOP-LEVEL navigation via the injected nav function, never window.open", () => {
  let navigatedTo = null;
  navigateToHandoff("http://127.0.0.1:4173/#token=abc", (url) => (navigatedTo = url));
  assert.equal(navigatedTo, "http://127.0.0.1:4173/#token=abc");
});

// --- probeDaemon: Safari (no LNA/PNA at all) + Chrome-managed-profile
// (LNA denied) both land here as a rejected fetch — click-gated only,
// caller decides when to call this, never automatic. ---

test("probeDaemon: daemon detected — well-formed /version response", async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => ({ daemon: "0.1.0", api: ["helm/1"] }) });
  const result = await probeDaemon({ fetchImpl });
  assert.equal(result.state, PROBE_STATE.DETECTED);
  assert.equal(result.daemon, "0.1.0");
  assert.deepEqual(result.api, ["helm/1"]);
});

test("probeDaemon: LNA denied (or absent) — fetch rejects, folds to clean browser mode", async () => {
  const fetchImpl = async () => {
    throw new Error("NotAllowedError: Local Network Access permission denied");
  };
  const result = await probeDaemon({ fetchImpl });
  assert.equal(result.state, PROBE_STATE.DENIED);
});

test("probeDaemon: nothing listening at all — same fetch-rejects path as LNA denial (indistinguishable by design)", async () => {
  const fetchImpl = async () => {
    throw new Error("Failed to fetch");
  };
  const result = await probeDaemon({ fetchImpl });
  assert.equal(result.state, PROBE_STATE.DENIED);
});

test("probeDaemon: something answers but isn't shaped like helmd (port-squat signal)", async () => {
  const fetchImpl = async () => ({ ok: true, json: async () => ({ unrelated: true }) });
  const result = await probeDaemon({ fetchImpl });
  assert.equal(result.state, PROBE_STATE.UNEXPECTED);
});

test("probeDaemon: something answers with a non-JSON body (port-squat signal)", async () => {
  const fetchImpl = async () => ({
    ok: true,
    json: async () => {
      throw new SyntaxError("not json");
    },
  });
  const result = await probeDaemon({ fetchImpl });
  assert.equal(result.state, PROBE_STATE.UNEXPECTED);
});

test("probeDaemon: non-2xx response is unreachable, not detected", async () => {
  const fetchImpl = async () => ({ ok: false, status: 500 });
  const result = await probeDaemon({ fetchImpl });
  assert.equal(result.state, PROBE_STATE.UNREACHABLE);
});

test("probeDaemon: requires an injected fetchImpl — never falls back to a bare global fetch", async () => {
  await assert.rejects(() => probeDaemon({}));
});

// --- negotiateCapabilities: P3-D6 skew handling ---

test("negotiateCapabilities: matching versions, fully compatible, no nudge", () => {
  const result = negotiateCapabilities(["helm/1"], ["helm/1"]);
  assert.deepEqual(result, { compatible: true, degraded: false, sharedVersions: ["helm/1"], updateNudge: false });
});

test("negotiateCapabilities: hosted UI newer than daemon — degraded but working, never a hard fail", () => {
  const result = negotiateCapabilities(["helm/1", "helm/2"], ["helm/1"]);
  assert.equal(result.compatible, true);
  assert.equal(result.degraded, true);
  assert.equal(result.updateNudge, true);
  assert.deepEqual(result.sharedVersions, ["helm/1"]);
});

test("negotiateCapabilities: daemon newer than UI (UI is a subset) — compatible, no nudge needed", () => {
  const result = negotiateCapabilities(["helm/1"], ["helm/1", "helm/2"]);
  assert.equal(result.compatible, true);
  assert.equal(result.degraded, false);
});

test("negotiateCapabilities: no shared version at all — incompatible, always a nudge", () => {
  const result = negotiateCapabilities(["helm/3"], ["helm/1"]);
  assert.equal(result.compatible, false);
  assert.equal(result.degraded, true);
  assert.equal(result.updateNudge, true);
  assert.deepEqual(result.sharedVersions, []);
});

test("UI_API_VERSIONS: matches the shape the daemon's SUPPORTED_API_VERSIONS ships (helm/N strings)", () => {
  assert.ok(UI_API_VERSIONS.every((v) => /^helm\/\d+$/.test(v)));
});
