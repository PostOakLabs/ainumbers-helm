// HELM-P3-V9 reconciliation gate — same discipline as
// verify-vendored-reconcile.test.mjs: proves the GENERATED, inlined runtime
// string (standalone-verifier-runtime.gen.mjs) is still functionally
// identical to the real ui/lib/verify-bundle.mjs it was compiled from, by
// running it (not just diffing text) against the same golden/tampered
// fixtures the Verify view's built-in demo uses. A silent drift here would
// mean every emailed bundle.zip ships a verifier that quietly disagrees with
// the app's own Verify view.
import { test } from "node:test";
import assert from "node:assert/strict";
import { VERIFIER_RUNTIME_JS } from "./standalone-verifier-runtime.gen.mjs";
import { buildStandaloneVerifierHtml } from "./standalone-verifier.mjs";
import { DEMO_PUBLIC_KEYS, DEMO_GOLDEN_BUNDLE, DEMO_TAMPERED_BUNDLE } from "../fixtures/verify-demo.mjs";

function loadRuntime() {
  // eslint-disable-next-line no-new-func
  return new Function(`${VERIFIER_RUNTIME_JS}\nreturn { verifyBundle, verifyAnchorBinding };`)();
}

test("inlined runtime: verifies a golden bundle", async () => {
  const { verifyBundle } = loadRuntime();
  const result = await verifyBundle(DEMO_GOLDEN_BUNDLE, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, true);
  assert.deepEqual(result.reasons, []);
});

test("inlined runtime: rejects a tampered bundle", async () => {
  const { verifyBundle } = loadRuntime();
  const result = await verifyBundle(DEMO_TAMPERED_BUNDLE, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.length > 0);
});

test("buildStandaloneVerifierHtml: embeds the bundle and keys as non-executing JSON, no external refs", () => {
  const html = buildStandaloneVerifierHtml({ bundle: DEMO_GOLDEN_BUNDLE, publicKeys: DEMO_PUBLIC_KEYS });
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /id="bundle-data"/);
  assert.match(html, /id="keys-data"/);
  assert.ok(html.includes(JSON.stringify(DEMO_GOLDEN_BUNDLE).replace(/</g, "\\u003c")));
  assert.doesNotMatch(html, /<script[^>]+src=/i, "must not reference any external script");
});

test("buildStandaloneVerifierHtml: a bundle_id containing '</script>' cannot break out of the embedded JSON", () => {
  const hostile = structuredClone(DEMO_GOLDEN_BUNDLE);
  hostile.manifest.predicate.bundle_id = "</script><script>window.pwned=1</script>";
  const html = buildStandaloneVerifierHtml({ bundle: hostile, publicKeys: DEMO_PUBLIC_KEYS });
  assert.doesNotMatch(html, /<\/script><script>window\.pwned/, "the raw closing tag must be escaped, not passed through verbatim");
  assert.ok(html.includes("\\u003c/script>\\u003cscript>window.pwned=1\\u003c/script>"), "the hostile string should survive, inertly, as escaped JSON text");
});

test("buildStandaloneVerifierHtml: renders a co-brand 'Presented by' section when bundle.presenter is set (HELM-P4-J2)", async () => {
  const withPresenter = { ...DEMO_GOLDEN_BUNDLE, presenter: { name: "Acme Bank Compliance", statement: "Reviewed by Acme Bank." } };
  const html = buildStandaloneVerifierHtml({ bundle: withPresenter, publicKeys: DEMO_PUBLIC_KEYS });
  assert.match(html, /Presented by/);
  assert.match(html, /Acme Bank Compliance/);

  const { verifyBundle } = loadRuntime();
  const result = await verifyBundle(withPresenter, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, true, "a presenter block must never affect the embedded runtime's own verification result");
});

test("buildStandaloneVerifierHtml: omits the presenter section entirely when bundle.presenter is absent", () => {
  const html = buildStandaloneVerifierHtml({ bundle: DEMO_GOLDEN_BUNDLE, publicKeys: DEMO_PUBLIC_KEYS });
  assert.doesNotMatch(html, /data-presenter="true"/);
});
