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
