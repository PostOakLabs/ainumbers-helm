# ui/vendored — port provenance (HELM-P2-S10)

Everything in this directory is hand-ported (no build step — the UI ships as
static files, D2 discipline), NOT re-vendored by a script. Each file below
traces to a hub source, which is itself vendored from the site repo at the
pinned SHA in `../../scripts/vendor.config.json` (currently
`bfa1bd621ca7147d2dc32f34326444159dfb0387`, `PostOakLabs/ainumbers.git`).

| ui/vendored file       | Ported from (hub)                                        | Transform applied |
|-------------------------|-----------------------------------------------------------|--------------------|
| `hash.mjs`               | `hub/vendored/ocg/kernels/_hash.mjs`                       | none (verbatim body) |
| `proof.mjs`              | `hub/vendored/ocg/kernels/_proof.mjs`                      | one import path: `./_hash.mjs` -> `./hash.mjs` |
| `der.mjs`                | `hub/vendored/ocg/kernels/_anchor-testutil.mjs` (DER/OID reader) + `hub/vendored/ocg/kernels/_rfc3161.mjs` (`parseRfc3161Token`'s field-walk) | Buffer -> Uint8Array; `Buffer.from(x,"base64")` -> `atob()`-based `base64ToBytes`; CMS signature/chain-of-trust verification dropped (no WebCrypto equivalent — structural-only, see file header) |
| `schema-validator.mjs`   | `scripts/lib/schema-validator.mjs` (helm's own, not site-vendored) | none (verbatim body) |
| `schemas/connector_contract.schema.mjs` | `schema/connector_contract.schema.json` (helm's own) | JSON literal wrapped as a default export |

`ui/lib/verify-envelope.mjs` and `ui/lib/verify-bundle.mjs` are not ports of a
vendored file — they mirror helm's own `hub/envelope.mjs` / `hub/bundle.mjs`
logic for the daemon-free Verify view (see each file's header).

## Reconciliation gate

`ui/lib/verify-vendored-reconcile.test.mjs` proves the ported copies above
still agree with their hub source, functionally (same hash, cross-verifying
ML-DSA-44 signatures, same RFC 3161 field extraction on a real pinned
fixture) rather than by byte-diff, since `der.mjs` is a genuine subset port
and can't be verbatim-compared. Runs under `npm test` (`scripts/test.mjs`
walks all `*.test.mjs`, `vendored/` dirs are excluded from discovery but this
file lives in `ui/lib/` so it runs).

**When `hub/vendored/ocg`'s pinned SHA bumps** (`npm run vendor`): if
`_hash.mjs`, `_proof.mjs`, `_anchor-testutil.mjs`, or `_rfc3161.mjs` changed
upstream, hand-resync the corresponding `ui/vendored/*.mjs` file per the
Transform column above, then re-run the reconciliation test — a failure means
the ui copy is now stale, not that the hub copy is wrong.
