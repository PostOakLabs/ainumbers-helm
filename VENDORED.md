# Vendored-tree inventory

Every vendored tree in this repository is config-driven (or manifest-verified) under
`scripts/verify-vendored.mjs`, carries a manifest with `sourceRepo` + `pinnedSha` +
`license`, and is byte-compared against its pinned upstream by
`node scripts/verify-vendored.mjs` (network) / its local-only functions offline.
Vendored code is never edited here — fix upstream, re-vendor, commit the new pin.

| Tree | Upstream | Pin (`pinnedSha`) | Writer | Manifest |
|---|---|---|---|---|
| `hub/vendored/ocg` | `github.com/PostOakLabs/ainumbers` (site) | `8a1e864…87be` | `scripts/vendor.mjs` (`vendor.config.json`) | `MANIFEST.json` |
| `hub/vendored/anchor-suite` | `github.com/PostOakLabs/anchor-suite` | `1aa6d22…d401` | `scripts/vendor-anchor.mjs` | `MANIFEST.json` |
| `hub/vendored/worker-otelspan` (HELM-OTEL-1) | `github.com/PostOakLabs/ainumbers-mcp-apps` (worker) | `44120172359257d9b68fe92b1162dfccc3e65b6d` | `scripts/vendor-worker.mjs` (`vendor-worker.config.json`): `otelspan.mjs` + the two shared-kernel modules it imports (`kernels/_hash.mjs`, `kernels/_proof.mjs`) in the source's original relative layout | `MANIFEST.json` |
| `hub/vendored/ssh-sig` | `github.com/wiktor-k/ssh-sig` | `cb28ef2…e3f5` | `scripts/vendor-ssh-sig.mjs` (`vendor-ssh-sig.config.json`) — design reference only, never executed | `MANIFEST.json` + `LICENSE` + `REFERENCE.md` |
| `hub/vendored/sigstore` | npm `@sigstore/*` mirror | pinned in `MANIFEST.json` | hand-staged (HELM-SIGSTORE-SEAMS lineage) | `MANIFEST.json` |
| `hub/vendored/sd-jwt` | npm `@sd-jwt/*` mirror | pinned in `MANIFEST.json` | hand-staged | `MANIFEST.json` |
| `ui/vendored` | heterogeneous (many upstreams) | per-entry in manifest | hand-ported | `ui/vendored/MANIFEST.json` |

`kernel-runner.mjs` additionally pins each kernel step to the vendored kernel's own
sha256 from `hub/vendored/ocg/MANIFEST.json` at run time.
