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
