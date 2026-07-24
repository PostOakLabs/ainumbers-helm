// HELM-P2-S10 done-criterion: proves the browser Verify view's ported vendored
// primitives (ui/vendored/{hash,proof,der}.mjs) have NOT drifted from the hub
// copies they were ported from (hub/vendored/ocg/kernels/_{hash,proof}.mjs,
// _anchor-testutil.mjs + _rfc3161.mjs), which are themselves vendored from the
// site repo at the pinned SHA recorded in ../../scripts/vendor.config.json.
// This is the machine-checked half of "one shared vendored source" — a
// comment saying "resync from the hub copy" is not a gate; this file is.
// Run this whenever hub/vendored/ocg is re-vendored (SHA bump): a failure here
// means ui/vendored needs a matching hand-resync (documented per-file in
// ui/vendored/PORT.md), not that the hub side is wrong.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { cgCanon as uiCgCanon, executionHash as uiExecutionHash } from "../vendored/hash.mjs";
import { cgCanon as hubCgCanon, executionHash as hubExecutionHash } from "../../hub/vendored/ocg/kernels/_hash.mjs";
import { ml_dsa44 as uiMlDsa44, sign as uiSign, verify as uiVerify, rawPubkeyToDidKey as uiRawPubkeyToDidKey } from "../vendored/proof.mjs";
import { ml_dsa44 as hubMlDsa44 } from "../../hub/vendored/ocg/kernels/_proof.mjs";
import { parseRfc3161MessageImprint } from "../vendored/der.mjs";
import { parseRfc3161Token } from "../../hub/vendored/ocg/kernels/_rfc3161.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

test("hash.mjs: cgCanon key-sort agrees with the hub copy on a mixed I-JSON vector", () => {
  const vector = { z: 1, a: [3, { y: 2, x: 1 }], m: "text", n: null };
  assert.deepEqual(uiCgCanon(vector), hubCgCanon(vector));
});

test("hash.mjs: executionHash is byte-identical to the hub copy for the same preimage", async () => {
  const policy_parameters = { activity: "reconcile_check", jurisdiction: "US", amount_usd: 100 };
  const output_payload = { decision: "approve", risk_score: 0.1 };
  const uiHash = await uiExecutionHash(policy_parameters, output_payload);
  const hubHash = await hubExecutionHash(policy_parameters, output_payload);
  assert.equal(uiHash, hubHash);
});

test("proof.mjs: ml_dsa44 keygen/sign/verify round-trips across ui <-> hub copies", () => {
  const { secretKey, publicKey } = uiMlDsa44.keygen();
  const msg = new TextEncoder().encode("HELM-P2-S10 reconciliation vector");
  const sig = uiMlDsa44.sign(msg, secretKey);
  // The hub copy's verify() must accept a signature produced by the ui copy —
  // proves the two vendored ml_dsa44 implementations are the same algorithm,
  // not just both self-consistent in isolation.
  assert.equal(hubMlDsa44.verify(sig, msg, publicKey), true);
  const hubSig = hubMlDsa44.sign(msg, secretKey);
  assert.equal(uiMlDsa44.verify(hubSig, msg, publicKey), true);
});

test("proof.mjs: securedDocument() empty-audit_signature fix (§16, site #589/#590) — sign->verify round-trips with no pre-existing audit_signature", async () => {
  const kp = await globalThis.crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const vm = await uiRawPubkeyToDidKey(kp.publicKey);
  const created = "2026-07-24T00:00:00Z";
  const bare = { record_type: "reconcile-check", subject_hash: "sha256:abc" };
  const signedBare = await uiSign(bare, { verificationMethod: vm, created, privateKey: kp.privateKey });
  assert.equal(await uiVerify(signedBare, kp.publicKey), true, "no pre-existing audit_signature round-trips");

  const emptyWrap = { record_type: "reconcile-check", subject_hash: "sha256:abc", audit_signature: {} };
  const signedEmpty = await uiSign(emptyWrap, { verificationMethod: vm, created, privateKey: kp.privateKey });
  assert.equal(await uiVerify(signedEmpty, kp.publicKey), true, "explicit empty audit_signature:{} pre-sign round-trips");
});

test("der.mjs: parseRfc3161MessageImprint agrees field-for-field with the hub's parseRfc3161Token on a real pinned TSA token", () => {
  const fixturePath = join(HERE, "../../hub/vendored/ocg/kernels/fixtures/anchor-binding.fixture.json");
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const rfc3161Binding = fixture.artifact.anchor_bindings.find((a) => a.type === "rfc3161-tst" || a.type === "rfc3161");
  assert.ok(rfc3161Binding, "fixture must carry an rfc3161 anchor binding to reconcile against");
  const proofB64 = rfc3161Binding.proof;

  const uiResult = parseRfc3161MessageImprint(proofB64);
  const hubResult = parseRfc3161Token(proofB64);

  assert.equal(uiResult.hashedMessageHex, hubResult.hashedMessage.toString("hex"));
  assert.equal(uiResult.policyOid, hubResult.policyOid);
  assert.equal(uiResult.serial, hubResult.serial);
  assert.equal(uiResult.genTime, hubResult.genTime);
});
