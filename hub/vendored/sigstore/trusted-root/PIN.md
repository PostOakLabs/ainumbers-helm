# Pinned Sigstore public-good trusted root — provenance (HELM-SIGSTORE-OFFLINE-VERIFY-1)

`trusted_root.json` in this directory is a **pinned, static snapshot** of the
Sigstore public-good instance's trust material (Fulcio CA chain, Rekor tlog
keys, CT log keys, TSA roots). It is consulted at verify time with **zero
network access** — this is the whole point of this row: an offline verifier
must never phone home to refresh its root of trust, not even to Sigstore's
own TUF repo.

## What "pinned" means here

This is **not** a TUF client embedded in helmd. A TUF client was deliberately
**not** built for this row (out of scope — see the row's fence) because it
would itself need network access to stay current, which is exactly the
capability offline verification must not have. Instead, this file is a
one-time, independently-checkable snapshot, refreshed by a human re-running
the steps below and committing the new file + updated digest.

## How this exact file was obtained and verified (2026-08-20)

Fetched the live Sigstore TUF repo's signed metadata chain directly (network
used only to CREATE this pin, never at verify time) and confirmed the target
file's content hash against the TUF-signed `targets.json` entry — the same
authenticity chain a full TUF client would establish, just performed by hand
once instead of automated per-verify:

1. `GET https://tuf-repo-cdn.sigstore.dev/timestamp.json` → `signed.meta["snapshot.json"].version = 165`
2. `GET https://tuf-repo-cdn.sigstore.dev/165.snapshot.json` → `signed.meta["targets.json"].version = 14`
3. `GET https://tuf-repo-cdn.sigstore.dev/14.targets.json` → `signed.targets["trusted_root.json"]` declares:
   ```json
   { "hashes": { "sha256": "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66" }, "length": 6787 }
   ```
4. `GET https://tuf-repo-cdn.sigstore.dev/targets/6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66.trusted_root.json`
   (content-addressed target path per TUF consistent-snapshot convention)
5. Independently recomputed `sha256(downloaded bytes)` and confirmed it
   equals the hash `targets.json` declared in step 3 **before** trusting the
   file — this is the load-bearing check: it proves the bytes below are the
   ones the TUF root-of-trust signed for, not merely "some file that happened
   to be served at that URL."

This repo does not re-verify the TUF root/timestamp/snapshot/targets
signatures themselves (that would require vendoring a TUF signature verifier
too, out of this row's fence) — the chain above is recorded so a future
re-pin, or a skeptical reviewer, can redo the same walk and compare.

## Pinned values

- **File:** `trusted_root.json`
- **sha256:** `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`
- **Byte length:** 6787
- **mediaType:** `application/vnd.dev.sigstore.trustedroot+json;version=0.1`
- **TUF targets.json version at pin time:** 14 (snapshot.json version 165)
- **Retrieved:** 2026-08-20
- **Source:** `https://tuf-repo-cdn.sigstore.dev/` (Sigstore public-good instance TUF repository)

## How this digest is recorded in an evidence bundle

`hub/sigstore-verify.mjs`'s `TRUSTED_ROOT_SHA256` constant is computed by
hashing this exact file at import time (never hand-copied from this doc), so
the two can never silently drift apart. Every sealed
`sigstore_bundle_verification` evidence-bundle object carries that digest in
its predicate (`trusted_root_sha256`) — a verifier reading the bundle later
can see exactly which pinned root the verification trusted, and can reject a
bundle asserting a digest that does not match a root they trust.

## Re-pinning

To refresh this file: redo the 5-step TUF walk above against the live CDN,
confirm the new content hash against the newly-signed `targets.json` entry,
overwrite `trusted_root.json`, update the "Pinned values" section above, and
re-run `node hub/sigstore-verify.test.mjs`'s genuine-bundle fixture check (a
stale trusted root that no longer covers current signing-cert validity
windows will start failing the GREEN control, which is the intended fail-safe
— see `SIGSTORE-STALE-ROOT-CAVEAT` in `hub/sigstore-verify.mjs`).
