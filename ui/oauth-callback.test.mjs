import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCallbackParams, relayAndRedirect, consumeRelayedResult } from "./oauth-callback.mjs";

function memoryStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, v),
    removeItem: (k) => map.delete(k),
  };
}

test("parseCallbackParams: happy path extracts code+state from query params, not a hash fragment", () => {
  assert.deepEqual(parseCallbackParams("?code=abc123&state=xyz"), { ok: true, code: "abc123", state: "xyz" });
});

test("parseCallbackParams: provider error is surfaced, not silently dropped", () => {
  assert.deepEqual(parseCallbackParams("?error=access_denied&error_description=user+cancelled"), {
    ok: false,
    error: "access_denied",
    errorDescription: "user cancelled",
  });
});

test("parseCallbackParams: missing code or state is a clear error", () => {
  assert.deepEqual(parseCallbackParams("?state=xyz"), { ok: false, error: "missing_code_or_state" });
  assert.deepEqual(parseCallbackParams("?code=abc"), { ok: false, error: "missing_code_or_state" });
  assert.deepEqual(parseCallbackParams(""), { ok: false, error: "missing_code_or_state" });
});

test("relayAndRedirect: stashes the result in sessionStorage, scrubs history BEFORE navigating, then navigates", () => {
  const storage = memoryStorage();
  const calls = [];
  const history = { replaceState: (...args) => calls.push(["replaceState", ...args]) };
  const loc = { pathname: "/helm/oauth-callback.html" };
  const navigate = (u) => calls.push(["navigate", u]);

  const result = { ok: true, code: "c1", state: "s1" };
  relayAndRedirect({ result, targetUrl: "./helm.html#/connect", storage, history, loc, navigate });

  assert.deepEqual(JSON.parse(storage.getItem("helm.oauth.callback")), result);
  assert.equal(calls[0][0], "replaceState");
  assert.equal(calls[0][3], "/helm/oauth-callback.html");
  assert.deepEqual(calls[1], ["navigate", "./helm.html#/connect"]);
});

test("consumeRelayedResult: one-shot read — a second call after consumption returns null", () => {
  const storage = memoryStorage();
  storage.setItem("helm.oauth.callback", JSON.stringify({ ok: true, code: "c", state: "s" }));
  assert.deepEqual(consumeRelayedResult(storage), { ok: true, code: "c", state: "s" });
  assert.equal(consumeRelayedResult(storage), null);
});
