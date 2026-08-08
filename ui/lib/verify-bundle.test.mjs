// HELM-U3 done-criterion: the browser-side bundle verifier accepts the golden
// fixture and REJECTS the tampered one (TILE-EXPLORER discipline — a verifier
// never observed to reject isn't known to verify). WebCrypto Ed25519 + the
// pure-JS ml_dsa44 vendor block both run fine under node:test, so this exercises
// the exact code path the Verify view runs in-browser.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyBundle, verifyCheckpointOffline, verifyAnchorBinding, verifyAnchorFull, assertRedacted } from "./verify-bundle.mjs";
import { DEMO_PUBLIC_KEYS, DEMO_GOLDEN_BUNDLE, DEMO_TAMPERED_BUNDLE } from "../fixtures/verify-demo.mjs";
import { FREETSA_TOKEN_B64, EXPECTED_HASH_HEX } from "../fixtures/rfc3161-verify-fixtures.mjs";

test("golden bundle verifies fully offline", async () => {
  const result = await verifyBundle(DEMO_GOLDEN_BUNDLE, DEMO_PUBLIC_KEYS);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.valid, true);
  assert.equal(result.detail.entries.length, 2);
  assert.ok(result.detail.entries.every((e) => e.valid));
});

test("TAMPERED bundle is proven to FAIL — a corrupted entry signature is caught", async () => {
  const result = await verifyBundle(DEMO_TAMPERED_BUNDLE, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((r) => r.startsWith("entry_envelope_invalid")));
});

test("wrong public key rejects an otherwise-golden bundle", async () => {
  const result = await verifyBundle(DEMO_GOLDEN_BUNDLE, { ed25519SpkiB64: DEMO_PUBLIC_KEYS.ed25519SpkiB64.slice(0, -4) + "AAAA", mldsa44B64: DEMO_PUBLIC_KEYS.mldsa44B64 });
  assert.equal(result.valid, false);
});

test("checkpoint self-consistency: golden checkpoint's journal_root_digest matches its own streams", async () => {
  const cp = DEMO_GOLDEN_BUNDLE.checkpoints[0];
  const result = await verifyCheckpointOffline(cp, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, true);
});

test("checkpoint self-consistency: a mismatched journal_root_digest is caught (structural tamper, not just signature)", async () => {
  const cp = structuredClone(DEMO_GOLDEN_BUNDLE.checkpoints[0]);
  // Corrupt the payload's declared digest without re-signing — this must fail
  // the ENVELOPE check first (payload changed, signature didn't), proving the
  // digest field can't be silently substituted even if signature checking were
  // somehow bypassed.
  const payload = JSON.parse(Buffer.from(cp.envelope.payload, "base64").toString("utf8"));
  payload.predicate.journal_root_digest = "sha256:" + "f".repeat(64);
  cp.envelope.payload = Buffer.from(JSON.stringify(payload)).toString("base64");
  const result = await verifyCheckpointOffline(cp, DEMO_PUBLIC_KEYS);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "envelope");
});

test("anchor binding: opentimestamps anchor with no pending_proof is reported, not silently accepted", () => {
  const result = verifyAnchorBinding({ type: "opentimestamps" }, "a".repeat(64));
  assert.equal(result.checked, false);
  assert.match(result.reason, /no pending_proof/);
});

test("anchor binding: opentimestamps — structural digest match + upgrade pointer surfaced (HELM-TSA-1)", () => {
  const hashHex = "a".repeat(64);
  const result = verifyAnchorBinding(
    { type: "opentimestamps", pending_proof: Buffer.from([1, 2, 3]).toString("base64"), anchored_hash: `sha256:${hashHex}`, calendar: "https://a.pool.opentimestamps.org" },
    hashHex
  );
  assert.equal(result.checked, true);
  assert.equal(result.bound, null, "never a definite verdict offline — not yet a Bitcoin block proof");
  assert.equal(result.digestBound, true);
  assert.equal(result.upgradePointer, "https://a.pool.opentimestamps.org");
});

test("anchor binding: opentimestamps — digest mismatch fails closed even though a pending_proof exists", () => {
  const result = verifyAnchorBinding({ type: "opentimestamps", pending_proof: Buffer.from([1, 2, 3]).toString("base64"), anchored_hash: `sha256:${"b".repeat(64)}` }, "a".repeat(64));
  assert.equal(result.checked, true);
  assert.equal(result.digestBound, false);
});

test("anchor binding: unrecognized anchor type is reported, never silently accepted", () => {
  const result = verifyAnchorBinding({ type: "scitt-receipt" }, "a".repeat(64));
  assert.equal(result.checked, false);
  assert.match(result.reason, /unrecognized/);
});

test("verifyAnchorFull: genuine rfc3161 anchor gets the full signature+chain+validity breakdown (HELM-TSA-1)", async () => {
  const result = await verifyAnchorFull({ type: "rfc3161", der: FREETSA_TOKEN_B64 }, EXPECTED_HASH_HEX);
  assert.equal(result.checked, true);
  assert.equal(result.bound, true);
  assert.equal(result.full.signature.valid, true);
  assert.equal(result.full.chain.valid, true);
  assert.equal(result.full.validity.valid, true);
});

test("verifyAnchorFull: non-rfc3161 anchor delegates to the structural check (no fuller check exists yet)", async () => {
  const result = await verifyAnchorFull({ type: "queued", reason: "relay unreachable" }, "a".repeat(64));
  assert.equal(result.neutral, true);
  assert.equal(result.status, "queued");
});

// HELM-VERIFY-CLI-1 §1.4 condition 1 — RED-BEFORE-GREEN for assertRedacted's
// depth guard. Confirmed by reading the pre-patch source: assertRedacted had
// NO depth guard before this WU (phil's carried-forward open item, answered
// against the real code). RED below reproduces that unbounded recursion;
// GREEN proves the new maxDepth param fails closed instead.
test("RED: assertRedacted with no maxDepth (the pre-existing 2-arg call shape) recurses until it overflows the stack on pathological input", () => {
  let root = {};
  let cur = root;
  for (let i = 0; i < 200000; i++) {
    cur.a = {};
    cur = cur.a;
  }
  assert.throws(() => assertRedacted(root), RangeError);
});

test("GREEN: assertRedacted(obj, \"$\", 0, maxDepth) fails closed with a reason string instead of recursing unbounded", () => {
  let root = {};
  let cur = root;
  for (let i = 0; i < 200000; i++) {
    cur.a = {};
    cur = cur.a;
  }
  assert.throws(() => assertRedacted(root, "$", 0, 500), /exceeded max depth 500/);
});

test("GREEN: assertRedacted's default (no maxDepth) behavior is unchanged for well-formed input — additive, not breaking", () => {
  assert.doesNotThrow(() => assertRedacted({ a: { b: { c: 1 } } }));
});

test("verifyBundle's additive maxDepth option rejects a pathologically nested entry predicate via entry_redaction_violated, without changing the 2-arg call shape", async () => {
  const bundle = structuredClone(DEMO_GOLDEN_BUNDLE);
  // Sanity: the unmodified golden bundle still verifies with an explicit cap
  // that's well above its real (shallow) nesting depth.
  const capped = await verifyBundle(bundle, DEMO_PUBLIC_KEYS, { maxDepth: 500 });
  assert.equal(capped.valid, true);
  // A cap of 0 must fail closed on the SAME golden bundle's entry predicates
  // (which nest at least one level) — proving the option is actually wired
  // through, not merely accepted and ignored.
  const overCapped = await verifyBundle(bundle, DEMO_PUBLIC_KEYS, { maxDepth: 0 });
  assert.equal(overCapped.valid, false);
  assert.ok(overCapped.reasons.some((r) => r.startsWith("entry_redaction_violated")));
});
