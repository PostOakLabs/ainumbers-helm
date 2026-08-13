# SSHSIG test fixtures — real `ssh-keygen -Y` output

Generated with real OpenSSH `ssh-keygen` (not hand-crafted bytes), per
`SIGN-EXTSIG-1` done-criterion #4 (goldens must come from the real binary,
never fabricated).

Regenerate with:

```bash
cd /tmp && mkdir -p sshsig-goldens && cd sshsig-goldens
ssh-keygen -t ed25519 -N "" -C "helm-test-signer" -f signer_key
ssh-keygen -t ed25519 -N "" -C "helm-other-signer" -f other_key
echo "helm countersign golden message — SIGN-EXTSIG-1" > message.txt
NS="helm-countersign@ainumbers.co"
ssh-keygen -Y sign -f signer_key -n "$NS" message.txt && mv message.txt.sig golden.sig
ssh-keygen -Y sign -f signer_key -n "wrong-namespace@example.com" message.txt && mv message.txt.sig wrong_namespace.sig
ssh-keygen -Y sign -f other_key -n "$NS" message.txt && mv message.txt.sig wrong_key.sig
echo "signer@helm-test $(cat signer_key.pub)" > allowed_signers
```

## Files

| File | What it is |
|---|---|
| `message.txt` | The signed content. |
| `allowed_signers` | OpenSSH `AllowedSignersFile` roster — `signer@helm-test` mapped to `signer_key`'s public key. |
| `golden.sig` | Valid signature: `signer_key` over `message.txt`, namespace `helm-countersign@ainumbers.co`. Must PASS. |
| `wrong_namespace.sig` | Same key + message, signed under namespace `wrong-namespace@example.com`. Must FAIL — namespace-enforcement regression fixture (phil condition #1 / the GitLab-class defect). |
| `wrong_key.sig` | Same namespace + message, signed by `other_key` (not in the roster under `signer@helm-test`). Must FAIL — proves the roster lookup cross-checks the signature's embedded key against the principal's registered key, not just "some signature verifies". |
| `signer_key.pub` / `other_key.pub` | Public keys, for reference — private keys were not committed. |

Cross-checked against real `ssh-keygen -Y verify` at generation time (not
just our own parser) — e.g. `wrong_namespace.sig` produces `Couldn't verify
signature: namespace does not match` from the real binary, confirming the
fixture exercises the intended failure mode and not an unrelated parse
error.

## CI-policy namespace fixtures (FV-SSHSIG-POLICY-KEY-1)

A second, throwaway ed25519 key exercises `CI_POLICY_SSHSIG_NAMESPACE`
("fv-policy-sign@ainumbers.co") — never the real production
`ci-policy-key@ainumbers.co` secret, which is never committed anywhere.
Regenerate with:

```bash
cd /tmp && mkdir -p sshsig-goldens-cipolicy && cd sshsig-goldens-cipolicy
ssh-keygen -t ed25519 -N "" -C "fv-policy-test-signer" -f test_key
ssh-keygen -t ed25519 -N "" -C "fv-policy-test-other" -f other_key
echo "fv policy sign golden message — FV-SSHSIG-POLICY-KEY-1" > ci_policy_message.txt
cp ci_policy_message.txt message.txt
NS="fv-policy-sign@ainumbers.co"
rm -f message.txt.sig; ssh-keygen -Y sign -f test_key -n "$NS" message.txt && mv message.txt.sig ci_policy_golden.sig
rm -f message.txt.sig; ssh-keygen -Y sign -f test_key -n "wrong-namespace@example.com" message.txt && mv message.txt.sig ci_policy_wrong_namespace.sig
rm -f message.txt.sig; ssh-keygen -Y sign -f other_key -n "$NS" message.txt && mv message.txt.sig ci_policy_wrong_key.sig
rm -f message.txt.sig; ssh-keygen -Y sign -f test_key -n "helm-countersign@ainumbers.co" message.txt && mv message.txt.sig ci_policy_signed_wrong_expected_namespace.sig
echo "ci-policy@helm-test $(cat test_key.pub)" > ci_policy_allowed_signers
```

| File | What it is |
|---|---|
| `ci_policy_message.txt` | The signed content for the CI-policy-namespace fixtures. |
| `ci_policy_allowed_signers` | Roster mapping `ci-policy@helm-test` to `test_key`'s public key. |
| `ci_policy_golden.sig` | Valid: `test_key` over `ci_policy_message.txt`, namespace `fv-policy-sign@ainumbers.co`. Must PASS when verified with `namespace: CI_POLICY_SSHSIG_NAMESPACE`. |
| `ci_policy_wrong_namespace.sig` | Same key+message, signed under `wrong-namespace@example.com`. Must FAIL. |
| `ci_policy_wrong_key.sig` | Same namespace+message, signed by `other_key` (not in `ci_policy_allowed_signers`). Must FAIL. |
| `ci_policy_signed_wrong_expected_namespace.sig` | `test_key` signing the SAME message under `helm-countersign@ainumbers.co` instead — proves a CI-policy key's helm-namespace signature is not fungible with a CI-policy-namespace one. Must FAIL when checked against `CI_POLICY_SSHSIG_NAMESPACE`. |
| `ci_policy_test_key.pub` | Public key, for reference — private key was not committed. |

Cross-checked against real `ssh-keygen -Y verify` at generation time — all
four failure fixtures produce `Couldn't verify signature: namespace does
not match` or `Could not verify signature.` from the real binary.

**The real production `ci-policy-key@ainumbers.co` private key is never a
test fixture.** It was generated once, its public half recorded in
`docs/allowed_signers` and `docs/TRUST.md`, and the private half handed to
the repo owner to install as a GitHub Actions secret — see
`docs/TRUST.md` "CI policy signing key" for the exact handoff.
