import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

const {
  emitSdJwt,
  presentSdJwt,
  verifySdJwt,
  generateSeed,
  seededSaltGenerator,
  BASE_PROFILE,
  VC_PROFILE,
  BASE_TYP,
  VC_TYP,
} = await import("./sdjwt-emit.mjs");

const { privateKey, publicKey } = generateKeyPairSync("ed25519");

// Fixed claim set: "name" is always visible; "operator_license" and
// "jurisdiction" are disclosable. iat is pinned so nothing time-dependent
// enters the emission.
const CLAIMS = Object.freeze({
  iss: "https://helm.example",
  iat: 1756700000,
  vct: "https://credentials.example/dao-operator",
  name: "Ada Operator",
  operator_license: "LIC-88112",
  jurisdiction: "Wyoming",
});
const FRAME = Object.freeze({ _sd: ["operator_license", "jurisdiction"] });

test("sdjwt-emit: emission round-trips through verify with every claim recovered", async () => {
  const seed = generateSeed();
  const { token, record } = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    seedHex: seed,
    signer: (await import("./sdjwt-emit.mjs")).ed25519Signer(privateKey),
  });

  const { payload, header } = await verifySdJwt(token, {
    verifier: (await import("./sdjwt-emit.mjs")).ed25519Verifier(publicKey),
  });
  assert.equal(header.typ, VC_TYP);
  assert.equal(payload.name, "Ada Operator");
  assert.equal(payload.operator_license, "LIC-88112");
  assert.equal(payload.jurisdiction, "Wyoming");
  assert.equal(payload.vct, CLAIMS.vct);
  // digest placeholders live in the signed payload, stripped from the unpacked claims
  const rawPayload = JSON.parse(Buffer.from(token.split("~")[0].split(".")[1], "base64url").toString("utf8"));
  assert.ok(Array.isArray(rawPayload._sd));
  assert.equal(rawPayload._sd_alg, "sha-256");
  assert.equal(payload._sd, undefined);
  assert.ok(record.profile.ratified === false);
});

test("sdjwt-emit: the recorded salt seed reproduces the token byte-for-byte", async () => {
  const seed = generateSeed();
  const signer = (await import("./sdjwt-emit.mjs")).ed25519Signer(privateKey);
  const first = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    seedHex: seed,
    signer,
  });
  const second = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    seedHex: seed,
    signer,
  });
  assert.equal(first.token, second.token);
  assert.equal(first.record.saltSeed.seed, seed);
  assert.equal(first.record.reproducible, true);

  const otherSeed = generateSeed();
  const third = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    seedHex: otherSeed,
    signer,
  });
  assert.notEqual(first.token, third.token);

  const unseeded = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    signer,
  });
  assert.equal(unseeded.record.saltSeed.seed, null);
  assert.equal(unseeded.record.reproducible, false);
});

test("sdjwt-emit: selective disclosure reveals one claim and withholds another", async () => {
  const signer = (await import("./sdjwt-emit.mjs")).ed25519Signer(privateKey);
  const verifier = (await import("./sdjwt-emit.mjs")).ed25519Verifier(publicKey);
  const { token } = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    seedHex: generateSeed(),
    signer,
  });

  const presented = await presentSdJwt(token, { operator_license: true });
  const { payload } = await verifySdJwt(presented, { verifier });

  // revealed
  assert.equal(payload.operator_license, "LIC-88112");
  // withheld: the claim is gone AND its plaintext rides nowhere in the bytes
  assert.equal(payload.jurisdiction, undefined);
  assert.ok(!presented.includes("Wyoming"));
  // always-visible claim survives presentation untouched
  assert.equal(payload.name, "Ada Operator");
  assert.equal(payload.vct, CLAIMS.vct);

  // presenting with no frame reveals every disclosure
  const full = await presentSdJwt(token, undefined);
  const fullPayload = (await verifySdJwt(full, { verifier })).payload;
  assert.equal(fullPayload.operator_license, "LIC-88112");
  assert.equal(fullPayload.jurisdiction, "Wyoming");
});

test("sdjwt-emit: base profile cites RFC 9901 as ratified and types the token sd-jwt", async () => {
  const signer = (await import("./sdjwt-emit.mjs")).ed25519Signer(privateKey);
  const baseClaims = { ...CLAIMS };
  delete baseClaims.vct;
  const { token, record } = await emitSdJwt({
    claims: baseClaims,
    disclosureFrame: { ...FRAME },
    profile: "base",
    seedHex: generateSeed(),
    signer,
  });
  const { header } = await verifySdJwt(token, {
    verifier: (await import("./sdjwt-emit.mjs")).ed25519Verifier(publicKey),
  });
  assert.equal(header.typ, BASE_TYP);
  assert.equal(record.profile.key, "base");
  assert.equal(record.profile.spec, "RFC 9901");
  assert.equal(record.profile.ratified, true);
  assert.equal(VC_PROFILE.label, "tracks draft");
  assert.equal(VC_PROFILE.ratified, false);
});

test("sdjwt-emit: VC profile rejects a missing vct and draft-forbidden disclosures", async () => {
  const signer = (await import("./sdjwt-emit.mjs")).ed25519Signer(privateKey);
  const noVct = { ...CLAIMS };
  delete noVct.vct;
  await assert.rejects(
    () =>
      emitSdJwt({
        claims: noVct,
        profile: "vc",
        signer,
      }),
    /vct/
  );
  for (const forbidden of ["vct", "iss", "exp"]) {
    await assert.rejects(
      () =>
        emitSdJwt({
          claims: { ...CLAIMS },
          disclosureFrame: { _sd: [forbidden] },
          profile: "vc",
          signer,
        }),
      /forbids selectively disclosing/
    );
  }
});

test("sdjwt-emit: a tampered signature fails verification", async () => {
  const signer = (await import("./sdjwt-emit.mjs")).ed25519Signer(privateKey);
  const verifier = (await import("./sdjwt-emit.mjs")).ed25519Verifier(publicKey);
  const { token } = await emitSdJwt({
    claims: { ...CLAIMS },
    disclosureFrame: { ...FRAME },
    profile: "vc",
    seedHex: generateSeed(),
    signer,
  });
  const parts = token.split("~");
  const sig = parts[0].split(".");
  const bytes = Buffer.from(sig[2], "base64url");
  bytes[bytes.length - 1] ^= 0x01;
  sig[2] = bytes.toString("base64url");
  const tampered = [sig.join("."), ...parts.slice(1)].join("~");
  await assert.rejects(() => verifySdJwt(tampered, { verifier }));
});

test("sdjwt-emit: seeded salt generator meets the 128-bit RFC 9901 entropy floor and never repeats", () => {
  const saltGenerator = seededSaltGenerator(generateSeed());
  const seen = new Set();
  for (let i = 0; i < 64; i++) {
    const salt = saltGenerator(16);
    assert.equal(salt.length, 22); // 16 bytes -> 22 base64url chars, 128 bits
    assert.equal(salt.includes("="), false);
    assert.ok(!seen.has(salt));
    seen.add(salt);
  }
  const other = seededSaltGenerator(generateSeed());
  assert.notEqual(saltGenerator(16), other(16));
  assert.throws(() => seededSaltGenerator("nothex"), /hex string/);
});
