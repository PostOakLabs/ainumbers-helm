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
| `schemas/anchor_queue_marker.schema.mjs` | `schema/anchor_queue_marker.schema.json` (helm's own, HELM-P3-A5) | JSON literal wrapped as a default export |
| `der-encode.mjs` | not a port — hand-rolled DER writer (HELM-P3-A5), the encode-side counterpart to `der.mjs`'s hand-rolled reader. Deliberately NOT ported from `hub/vendored/anchor-suite/lib/tsq.mjs`, which builds the identical TLV shape via the ~24k-line vendored pkijs bundle — bringing that into `ui/` would break D2 (static, no build step, no heavyweight dep for one small request). See the file's own header. |
| `qrcodegen.js`            | [Project Nayuki QR Code generator library](https://www.nayuki.io/page/qr-code-generator-library), `javascript/qrcodegen.js`, tag `v1.5.0` (MIT License, full header preserved in-file) | none (verbatim). Not a port of a hub source — a third-party vendor for HELM-P3-V9's auditor PDF QR code (offline, zero-network). Wrapped as a string constant by `scripts/gen-qrcodegen-runtime.mjs` -> `ui/lib/qrcodegen-runtime.gen.mjs` so `ui/lib/auditor-pdf.mjs` can embed it with no fs access. |
| `pptxgen.bundle.js`       | [PptxGenJS](https://gitbrent.github.io/PptxGenJS/) `4.0.1`, `dist/pptxgen.bundle.js` from the npm tarball (MIT License, full header preserved in-file; bundles JSZip so it is fully self-contained) | none (verbatim body, MIT header + a short provenance/no-network note prepended). Third-party vendor for HELM-P4-A2's committee-deck `.pptx` export — loaded lazily as a plain `<script>` (UMD global `window.PptxGenJS`) only when the export button is clicked, never on initial page load. Client-side OOXML generation only; Helm's caller (`ui/lib/committee-pptx.mjs`) only ever passes image `data:` URIs, never a `path` URL, so the library's optional `XMLHttpRequest` image-fetch path is never exercised. |
| `pkijs.bundle.mjs` (HELM-TSA-1) | `hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs` (BSD-3-Clause + MIT, see NOTICE) | none (byte-identical copy — see below for why it's copied, not cross-imported). Loaded lazily via `ui/lib/rfc3161-verify.mjs`'s `dynamic import()`, only when a live rfc3161 anchor is actually verified, so the ~800KB bundle never loads on initial page view (same lazy pattern as `pptxgen.bundle.js` above). |
| `tsa-roots.mjs` (HELM-TSA-1) | not a port — pinned RFC 3161 TSA root certificates (DigiCert, Sectigo, FreeTSA), captured live per the file's own header. | n/a |

`ui/lib/verify-envelope.mjs` and `ui/lib/verify-bundle.mjs` are not ports of a
vendored file — they mirror helm's own `hub/envelope.mjs` / `hub/bundle.mjs`
logic for the daemon-free Verify view (see each file's header).

**HELM-TSA-1 exception to the "no pkijs in `ui/`" rule above (der.mjs row):** the
signature/chain-of-trust half of RFC 3161 verification that row's Transform column
calls out as "dropped — no WebCrypto equivalent" turned out to have one: WebCrypto
CAN verify a raw CMS signature and build a cert chain, but pkijs's own
`SignedData`/`CertificateChainValidationEngine` classes do that far more safely
than a second hand-rolled ASN.1 walker would. `der.mjs`'s existing hand-rolled
messageImprint check (`parseRfc3161MessageImprint`) stays as-is and still runs
first; pkijs only does the signature+chain+validity work der.mjs's header always
said browsers couldn't do offline. **Why `pkijs.bundle.mjs` is COPIED into
`ui/vendored/` rather than cross-imported from `hub/vendored/anchor-suite/`:**
the UI ships as static files served only from the `ui/` tree
(`hub/ui-manifest.mjs`'s `UI_ASSETS` allowlist, consulted by `hub/static.mjs`) —
`hub/` itself is never HTTP-reachable, so a browser `import()` reaching outside
`ui/` would 404 in the deployed app even though it resolves fine under `node
--test`. The copy is proven byte-identical to the hub source by
`ui/lib/pkijs-vendor-reconcile.test.mjs`, which re-runs on every `npm test` —
resync by re-copying `hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs` if that
gate ever goes red (e.g. after an anchor-suite re-vendor).

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
