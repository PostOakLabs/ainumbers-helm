# Sigstore bundle test fixtures — a real, published attestation (not fabricated)

Per the same discipline `fixtures/sshsig/README.md` documents (goldens must
come from a real signer, never hand-crafted bytes): `golden.sigstore.json` is
a genuine Sigstore bundle, not synthesized for this test.

## Provenance

`golden.sigstore.json` is the `bundle` field of the `https://slsa.dev/provenance/v1`
attestation npm publishes for `@sigstore/verify@4.1.2` (the same package this
row vendors for the verifier itself — a real GitHub Actions OIDC-signed,
Rekor-logged SLSA provenance attestation, produced by `npm publish
--provenance` off `sigstore/sigstore-js`'s release workflow). Retrieved
2026-08-20 via:

```
GET https://registry.npmjs.org/-/npm/v1/attestations/%40sigstore%2Fverify@4.1.2
```

— the response's `attestations[]` array has two entries (npm publish attestation
+ SLSA provenance); `.bundle` of the `https://slsa.dev/provenance/v1` entry was
written out verbatim as `golden.sigstore.json`.

## Files

| File | What it is |
|---|---|
| `golden.sigstore.json` | Real Sigstore bundle (Fulcio cert + Rekor tlog entry + DSSE envelope) for `@sigstore/verify@4.1.2`'s SLSA provenance. Must PASS `verifySigstoreBundleOffline()` against the pinned trust root in `hub/vendored/sigstore/trusted-root/`. |
| `tampered.sigstore.json` | `golden.sigstore.json` with byte 0 of `dsseEnvelope.signatures[0].sig` XORed with `0xff` (one flipped bit in the signature, everything else byte-identical). Must FAIL — `hub/sigstore-verify.test.mjs`'s RED control. |
| `message-signature.sigstore.json` | messageSignature (detached-signature) bundle over known artifact bytes, signed with a throwaway self-described fixture key. Exercise material for the messageSignature parameter contract (`artifact: { bytes }`, never a digest-only reference). Must FAIL full verification at some stage (self-signed cert does not chain to the pinned Fulcio root; no tlog entry) — it exists to prove the branch runs and fails closed, never that the bundle is trustworthy. |

## Regenerating

```bash
curl -s "https://registry.npmjs.org/-/npm/v1/attestations/%40sigstore%2Fverify@4.1.2" \
  | node -e 'let d="";process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{
      const j=JSON.parse(d);
      const slsa=j.attestations.find(a=>a.predicateType==="https://slsa.dev/provenance/v1");
      require("fs").writeFileSync("golden.sigstore.json", JSON.stringify(slsa.bundle, null, 2));
    })'
node -e '
  const fs=require("fs");
  const j=JSON.parse(fs.readFileSync("golden.sigstore.json","utf8"));
  const sig=Buffer.from(j.dsseEnvelope.signatures[0].sig,"base64");
  sig[0]^=0xff;
  j.dsseEnvelope.signatures[0].sig=sig.toString("base64");
  fs.writeFileSync("tampered.sigstore.json", JSON.stringify(j, null, 2));
'
```

`message-signature.sigstore.json` was generated once with the OpenSSL CLI and
committed with its inputs baked in (deterministic content, no runtime crypto,
no network):

```bash
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -days 36500 \
  -subj "/CN=helm-message-signature-fixture/O=AINumbersHelmFixture"
printf 'helm messageSignature fixture: the artifact bytes this bundle signs. Never verify as genuine: self-signed fixture key.\n' > artifact.txt
openssl dgst -sha256 -sign key.pem -out sig.der artifact.txt
openssl x509 -in cert.pem -outform DER -out cert.der
```

then assembled with `node` into the v0.3 bundle shape (`mediaType`,
`verificationMaterial.certificate.rawBytes` = base64 DER of `cert.der`,
empty `tlogEntries`, and `messageSignature.signature` / `messageDigest`
from `sig.der` / `sha256(artifact.txt)`). The artifact's sha256 is
`640d9a54cf56c1a0bb277ea3782a25420fc50a82059340c88a89cb0f0f62098f` and is
pinned in `hub/sigstore-verify.test.mjs`, which re-derives it from the
artifact bytes on every run. A green messageSignature verification vector
cannot be produced offline at all (it would require a genuine Fulcio-issued
certificate and a Rekor log entry); every reachable verification stage for
this fixture must therefore fail closed, which is what the tests assert.
