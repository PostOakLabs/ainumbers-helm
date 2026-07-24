// HELM-P4-J2 done-criterion: the presenter co-brand block renders in the
// "Presented by" section and — the load-bearing property — swapping or
// stripping bundle.presenter never changes verifyBundle()'s result, since
// presenter lives outside manifest/objects/checkpoints entirely.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isValidPresenter, renderPresenterHtml } from "./presenter.mjs";
import { verifyBundle } from "./verify-bundle.mjs";
import { validate } from "../../scripts/lib/schema-validator.mjs";
import { readFileSync } from "node:fs";
import { DEMO_PUBLIC_KEYS, DEMO_GOLDEN_BUNDLE, DEMO_TAMPERED_BUNDLE } from "../fixtures/verify-demo.mjs";

const PRESENTER_SCHEMA = JSON.parse(readFileSync(new URL("../../schema/presenter.schema.json", import.meta.url), "utf8"));

const VALID_PRESENTER = { name: "Acme Bank Compliance", logo: "data:image/png;base64,AAAA", statement: "Reviewed and shared by Acme Bank." };

test("valid presenter passes schema + isValidPresenter", () => {
  assert.deepEqual(validate(PRESENTER_SCHEMA, VALID_PRESENTER), []);
  assert.equal(isValidPresenter(VALID_PRESENTER), true);
});

test("presenter without name fails schema + isValidPresenter", () => {
  assert.ok(validate(PRESENTER_SCHEMA, { statement: "no name" }).length > 0);
  assert.equal(isValidPresenter({ statement: "no name" }), false);
});

test("presenter logo must be a data-URI, never a remote fetch", () => {
  const remote = { name: "Acme", logo: "https://acme.example/logo.png" };
  assert.ok(validate(PRESENTER_SCHEMA, remote).length > 0);
  assert.equal(isValidPresenter(remote), false);
});

test("renderPresenterHtml renders a distinct 'Presented by' section with name, logo, statement", () => {
  const html = renderPresenterHtml(VALID_PRESENTER);
  assert.match(html, /Presented by/);
  assert.match(html, /data-presenter="true"/);
  assert.match(html, /Acme Bank Compliance/);
  assert.match(html, /Reviewed and shared by Acme Bank\./);
  assert.match(html, /data:image\/png;base64,AAAA/);
});

test("renderPresenterHtml returns empty string when there is no presenter", () => {
  assert.equal(renderPresenterHtml(undefined), "");
  assert.equal(renderPresenterHtml(null), "");
});

test("renderPresenterHtml escapes hostile presenter fields (no HTML injection via name/statement)", () => {
  const html = renderPresenterHtml({ name: '<img src=x onerror=alert(1)>', statement: "</section><script>alert(2)</script>" });
  assert.doesNotMatch(html, /<img src=x onerror/);
  assert.doesNotMatch(html, /<script>alert/);
});

test("swapping the presenter on an otherwise-golden bundle does NOT affect verifyBundle()'s result", async () => {
  const withPresenter = { ...DEMO_GOLDEN_BUNDLE, presenter: VALID_PRESENTER };
  const swapped = { ...DEMO_GOLDEN_BUNDLE, presenter: { name: "A Completely Different Reseller" } };
  const stripped = { ...DEMO_GOLDEN_BUNDLE };
  delete stripped.presenter;

  const [r1, r2, r3] = await Promise.all([
    verifyBundle(withPresenter, DEMO_PUBLIC_KEYS),
    verifyBundle(swapped, DEMO_PUBLIC_KEYS),
    verifyBundle(stripped, DEMO_PUBLIC_KEYS),
  ]);
  assert.equal(r1.valid, true);
  assert.equal(r2.valid, true);
  assert.equal(r3.valid, true);
  assert.deepEqual(r1.reasons, r2.reasons);
  assert.deepEqual(r2.reasons, r3.reasons);
});

test("a presenter swap on a TAMPERED bundle still fails for the tampering, unaffected by presenter", async () => {
  const swapped = { ...DEMO_TAMPERED_BUNDLE, presenter: VALID_PRESENTER };
  const result = await verifyBundle(swapped, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("entry_envelope_invalid")));
});
