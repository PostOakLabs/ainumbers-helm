# Verifying Helm attestations with the policy engines you already run

Helm evidence bundles already ship as self-verifying artifacts (`bundle.json`
+ `verify.html` offline — see `docs/TRUST.md`). Some gates, though, are run
by a platform team's existing policy machinery, not by Helm's own verifier.
`helmd export-intoto` bridges that gap: it wraps one bundle's digest-level
record as an **in-toto Statement v1** with the registered predicate type

```
https://ainumbers.co/attestation/helm-run/v1
```

inside the same dual-signature DSSE envelope every Helm object already gets
(Ed25519 MUST per RFC 9964 `EdDSA`, plus ML-DSA-44 SHOULD), signed with the
install's own at-rest keys. The predicate carries ids, digests, step digests,
and trust labels only — never raw payload bytes; the schema is pinned at
`schema/predicates/helm-run-v1.schema.json`.

## Export

```sh
helmd export-intoto bundle.json --out statement.json
```

Exit codes: `0` written, `1` export failure (not an evidence bundle,
secret-shaped field, self-inconsistent provenance, schema failure, key
material unavailable — nothing is written), `2` usage error. No daemon, no
network. The receiver verifies against the install's public keys, printed by:

```sh
helmd bilat-pubkey --json
```

Helmd itself writes a DSSE envelope whose `payloadType` is
`application/vnd.in-toto+json` (base64 payload of the statement). Nothing
below forks the verifier: sigstore-js is *reference reading* for how these
tools consume envelopes, never vendored into Helm.

## Recipe 1 — cosign verify-attestation

`cosign` verifies DSSE attestations by predicate type. Shape only — install
and trust (key handling) stay in your own environment:

```sh
# publicKeys.json = `helmd bilat-pubkey --json` output saved verbatim
cosign verify-attestation \
  --type https://ainumbers.co/attestation/helm-run/v1 \
  --key <public-keys-file-or-keyref> \
  <artifact-reference-or-bundle.json>
```

What a *valid* result must satisfy: the payload's `predicateType` matches the
type above, the envelope verifies against the supplied public key, and the
statement's `subject` digest equals the artifact you're gating on (for Helm
this is the bundle file's own sha256 — `predicate.bundle_sha256` and
`subject[0].digest.sha256` are the same value by construction). Note that a
cosign envelope travels bundle-of-keys differently; when instead you have a
raw Helm DSSE envelope file (`statement.json`), the equivalent offline check
is `helmd verify bundle.json --keys publicKeys.json` plus the digest match
above.

## Recipe 2 — Kyverno verifyImages.attestations

Cluster policy example (shape only — put your key in a Kyverno-compatible
trust store; in-toto predicate matching is where Helm's predicate type plugs
in):

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-helm-run-attestation
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-helm-run-attestation
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      # helmd bilat-pubkey --json  (ed25519SpkiB64 decoded to PEM)
                      -----BEGIN PUBLIC KEY-----
          attestations:
            - predicateType: https://ainumbers.co/attestation/helm-run/v1
              conditions:
                - all:
                    - key: "{{ predicate.run_id }}"
                      operator: NotEquals
                      value: ""
                    - key: "{{ predicate.trust_labels }}"
                      operator: AnyIn
                      value: ["kernel_verified", "hash_verified"]
```

The `conditions` block is where your own gate lives — pass/fail on the same
digest-level fields the exporter guarantees (`run_id`, `execution_hash`,
`kernel_digest`, `trust_labels`), nothing more.

## Recipe 3 — offline `gh attestation verify` on a release tarball

Release artifacts themselves (the helm tarball, not run bundles) are attested
in CI by `actions/attest-build-provenance` (see
`.github/workflows/release.yml`). Verify offline with the bundle + root the
workflow emitted, no network after download:

```sh
gh attestation verify \
  helmd-<platform>-<version>.tar.gz \
  --bundle <attestation.jsonl> \
  --custom-trusted-root <root.json>
```

`--bundle` is the JSON-lines attestation list `gh attestation download`
saved, and `--custom-trusted-root` is the same trust root pinned locally —
both travel with the release out-of-band, matching Helm's no-key-registry
design (Helm has no key registry by design; trust material travels out of
band and is verified by digest).

## Recipe 4: verify a bundle in CI with the `helmd verify` GitHub Action

The repo's root `action.yml` is a composite action (no third-party actions,
no npm registry) for consuming pipelines: it downloads the pinned Helm
release tarball with `curl`, checks its sha256, and runs
`helmd verify <bundle> --keys <keys> --json` offline, exposing the verdict
as `valid` / `reason` outputs. Pin `helm_sha256` to the digest of the source
tarball for your `helm_version` (re-pin per version):

```yaml
- uses: PostOakLabs/ainumbers-helm@2026.9.10
  id: helm
  with:
    bundle: evidence/bundle.json          # from `helmd check --out`
    keys: evidence/publicKeys.json        # out-of-band, see Recipe 1
    helm_version: 2026.9.10
    helm_sha256: 847cbf378be7163762674f1389bae2f4ae5e8af1f90d72c58509eb3fdacfbef9
- run: |
    test "${{ steps.helm.outputs.valid }}" = "true" || {
      echo "bundle rejected: ${{ steps.helm.outputs.reason }}"; exit 1; }
```

An INVALID verdict is a result, not an action failure: read
`steps.helm.outputs.valid`; only a digest mismatch or usage error fails the
step. The action self-tests on every `action.yml` change
(`.github/workflows/verify-action-selftest.yml`) against the repo's
golden + tampered demo bundles.

## What this page deliberately does not do

- It does not vendor sigstore-js or cosign into Helm — zero dependencies
  stays load-bearing (`bin/zero-dep.test.mjs`).
- It does not publish Helm's own keys anywhere; `helmd bilat-pubkey` remains
  the out-of-band channel, exactly as for `helmd verify`.
- The Kyverno/cosign snippets are shape examples for the reader's own
  environment, not executed anywhere in CI.
