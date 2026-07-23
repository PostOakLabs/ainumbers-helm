# Helm Phase-2 launch readiness — GO/NO-GO

**Date:** 2026-07-23 · **WU:** `HELM-P2-LAUNCH` · **Spec:** `HELM-PHASE2-LAUNCH-SPEC.md` §2 · **HEAD:** `0322547`

## Verdict: **GO**

All §10 acceptance gates green, `release:verify` green against the real v0.1.0 release assets, packaging manifests regenerated, link-swap draft PR opened and held. Two real bugs were found and fixed while re-running the gates (below) — both are now in `main` and covered by tests/evidence.

---

## §10 gate results (Phase 2 exit)

| # | Gate | Result | Evidence |
|---|---|---|---|
| 1 | Catalog / compile integrity | ✅ GREEN | `packs:check`: 207/207 compiled fresh, pinned `bfa1bd6…`. `packs:parity`: 535/535 nodes byte-identical across 207 packs, 0 divergences. |
| 2 | Self-integration egress | ✅ GREEN | Covered by the offline test suite: DNS-rebind block + pin/unpin regression (`HELM-P2-R11-F1`), STARTTLS servername fix (`HELM-P2-R11-F2`), unapproved-host block + transcript, redirect-to-non-allowlisted block, secret-never-in-log grep-gate (`hub/server.test.mjs`, `hub/connector.test.mjs`, `hub/vault.test.mjs`) — all passing, see row 7. |
| 3 | Pairing welcome-state | ✅ GREEN (was RED, fixed) | Tokenless load of `/` now renders the full welcome-state (title, 3-step instructions, install link, "pair by hand" disclosure) instead of an empty `<main>`. Verified live via browser against a fresh `helmd` instance. |
| 4 | GUI compact default + Help daemon-absent | ✅ GREEN (was RED, fixed) | Compact density confirmed default (`document.documentElement.dataset.density === "compact"`, toggle button reads "Comfortable"). `/#/help` renders its full content (view descriptions, core loop, pairing/troubleshooting) with no token and no daemon connection. |
| 5 | Guardrails intact | ✅ GREEN | Egress default-deny unchanged (tests above); no AGPL/n8n/Windmill code added; `packs:check`/`packs:parity` above cover manifest JCS/§26-conformance and digestibility. |

## Release integrity

| Check | Result | Evidence |
|---|---|---|
| `release:verify` | ✅ GREEN | Ran against the real `v0.1.0` GitHub release assets (downloaded via `gh release download`): `{"ok":true,"version":"0.1.0","artifactCount":4}`. Dual-signature (Ed25519 + ML-DSA-44) valid, all 4 artifact digests match. |
| `release:packaging` | ✅ GREEN | `gen-packaging-manifests`: wrote 7/7 manifests (winget × 3, homebrew × 1, npm × 3) for v0.1.0. |
| Offline test suite | ✅ GREEN | 177 tests, 173 pass, 0 fail, 4 skipped (live third-party network tests, gated behind `HELM_LIVE_NET` per `test-support/live.mjs` — expected offline). |
| Lint | ✅ GREEN | `npm run lint` → `lint: OK`. |

## Bugs found + fixed during this gate sweep

1. **`views/help.mjs` missing from the servable-UI allowlist** (`hub/ui-manifest.mjs`). `app.mjs` statically imports every `VIEWS` entry including Help; the missing allowlist entry 401'd that import, which aborted the whole `<script type=module>` graph before `boot()` ever ran — so `<main>` stayed empty on every tokenless load (gates 3 and 4 both silently broken). Fixed by adding `"views/help.mjs"` to `FILES` in `hub/ui-manifest.mjs`; added a regression test (`hub/server.test.mjs`). Commit `f4b7efe`.
2. **`verify-release-manifest.mjs`'s CLI self-invoke check was Windows-broken.** `import.meta.url === \`file://${process.argv[1]}\`` never matches on Windows (backslash path, missing extra slash for the drive letter), so `npm run release:verify` silently no-op'd and exited 0 — a false green on every Windows dev machine. Fixed with `pathToFileURL(process.argv[1]).href`. Commit `0322547`.

Both fixes are in `PostOakLabs/ainumbers-helm` `main` as of this report.

## Site link-swap (held)

Draft PR opened on `PostOakLabs/ainumbers` (site repo): **[#574](https://github.com/PostOakLabs/ainumbers/pull/574)** — swaps `helm.html`'s four `download/v0.1.0/<asset>` buttons to `releases/latest/download/<asset>`. **HELD, not merged** — it 404s until the repo is public and a GA tag exists.

---

## Tim-gated go-public runbook (ordered)

Everything above is done. These four steps are explicitly out of this WU's scope (irreversible / credential-bearing / outward-facing) and are Tim's:

1. **Flip `PostOakLabs/ainumbers-helm` public** (GitHub repo settings).
2. **Cut the GA tag** (non-pre-release): generate/confirm release keys → commit public keys → `gh secret set --body-file -` → push the GA tag → confirm the release workflow ran tests and produced the dual-signed manifest.
3. **(Optional) external publishes** — winget / brew / npm, from the packaging manifests already regenerated in this WU (`dist/packaging/`, not committed — gitignored, regenerate with `npm run release:packaging` against the GA `dist/`).
4. **Merge the held link-swap PR** ([#574](https://github.com/PostOakLabs/ainumbers/pull/574)) — a session does this once steps 1–2 are done: `gh pr ready 574 && gh pr merge 574`.

No residual findings block GO. Phase 2 closes once steps 1–4 above are executed.
