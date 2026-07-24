# Releasing

Releases are automated by [release-please](https://github.com/googleapis/release-please) (`.github/workflows/release-please.yml`, SHA-pinned per SO #17 — the only third-party action in this program).

## How it works

1. Every push to `main` runs release-please. It reads squash-merge PR titles since the last release, parsed as [Conventional Commits](https://www.conventionalcommits.org/), and keeps a standing **release PR** up to date with the computed next version + `CHANGELOG.md` entry.
2. Merging that PR (squash, into `main`) makes release-please create the `vN.N.N` tag and a GitHub Release.
3. The tag push triggers the existing `.github/workflows/release.yml` pipeline: three-platform SEA build → pauses at the `release` Environment for one approval click → signed release manifest → verify (fail-closed) → GitHub release (GA tags self-promote to `latest`) → `publish-npm` (GA tags only).

## Commit type → version bump

PR titles are enforced as Conventional Commits (`.github/workflows/pr-title-lint.yml`, HELM-REL-AUTO-2). release-please maps them:

| Commit type | Bump |
|---|---|
| `fix:` | patch |
| `feat:` | minor |
| `feat!:` / `fix!:` / any type with `!` or a `BREAKING CHANGE:` footer | major |
| `docs:`, `chore:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:`, `revert:` | no release (grouped in changelog under `chore`/etc., no version bump on its own) |

## Pinning a specific version

Add a `Release-As: X.Y.Z` footer to a commit (or PR title body) to force the next release PR to that exact version, overriding the computed bump. Used once, at program start, to pin the first public GA to **v0.2.0** (A2 — minor over the 0.1.0 pre-release, reflecting Phase-2 packs + connectors) rather than whatever `fix`/`feat` commits would have computed.

## Local shift-left gates (HELM-SHIFTLEFT-1)

Run `node scripts/setup-hooks.mjs` once per clone (worktrees inherit it). It points `core.hooksPath` at the version-controlled `.githooks/`:

- `.githooks/commit-msg` validates the commit subject against the same Conventional Commit rule `PR Title Lint` enforces in CI, via the shared `lintTitle()` in `scripts/pr-title-lint.mjs` — one validator, so local and CI can never drift.
- `.githooks/pre-push` runs the full `ci.yml` job in order (lint → test → schemas → vendored integrity → parity gate → sea dry-run) plus a Conventional-Commit check over every commit in the push, so green locally means green in CI.

**A PR title can't be validated pre-push — it doesn't exist until `gh pr create` runs.** The fix is upstream of that: validate the commit subject locally, then always open PRs with `gh pr create --fill` so the title inherits the already-validated subject. That combination is what actually prevents a red `PR Title Lint` (see PR #48, which failed because the PR title was hand-typed instead of inherited).

Both hooks accept `--no-verify` as an emergency bypass; CI stays the real backstop.

## Merge flow

1. Land normal feature/fix PRs against `main` with Conventional-Commit titles — open them with `gh pr create --fill` (see above) so the title is inherited from an already-validated commit subject.
2. release-please keeps its release PR current automatically — no manual editing of `CHANGELOG.md` or the manifest.
3. When ready to cut a release, review and squash-merge the release PR. That's the only manual step besides the release approval click.

## npm publishing (GA releases only)

GA tags (`vN.N.N`, not `-rc`) publish `@ainumbers/helm-cli` to npm via the `publish-npm` job in `release.yml`. It uses **OIDC trusted publishing** — no npm token lives in this repo. The npm package (`packaging/npm/`) is a thin launcher: `postinstall` downloads the platform-matched `helmd` SEA binary from the matching GitHub release and verifies it against a sha256 baked in from the signed release manifest at build time (HELM-H8) — no source is trusted at install time beyond that pinned digest.

**Deferred (HELM-REL-NPM-DEFER, 2026-07-23):** `publish-npm` is gated behind repo variable `vars.NPM_PUBLISH_ENABLED` (default unset/false), so it skips cleanly instead of red-failing — npm has no way to attach a trusted publisher to a package that doesn't exist yet, and the signed GitHub release stands on its own for GA. **Revive trigger:** once the npm trusted publisher is attached (below) via a one-time bootstrap publish, set `vars.NPM_PUBLISH_ENABLED = 'true'` in repo settings → Variables. No workflow change needed — OIDC wiring is already in place.

### One-time setup (Tim, manual — cannot be automated from this repo)

Trusted publishing is configured on the **npm side**, once, after the repo goes public:

1. Sign in to npmjs.com, go to the `@ainumbers/helm-cli` package's **Settings → Trusted Publisher** (or create the package first — first publish under a trusted publisher can also be done via a one-time classic token, see npm's trusted-publishing docs for the bootstrap path).
2. Add a GitHub Actions trusted publisher:
   - **Organization/repo:** `PostOakLabs/ainumbers-helm`
   - **Workflow filename:** `release.yml`
   - **Environment:** `release`
3. No token is stored anywhere — the `publish-npm` job's `id-token: write` permission lets npm verify the run's OIDC identity against this config at publish time.

Until this is configured AND `vars.NPM_PUBLISH_ENABLED` is flipped to `'true'`, `publish-npm` skips on every GA release — the GitHub release itself is unaffected since it publishes in the job before `publish-npm`.

**2FA on the npm side (Tim, manual, one-time):** every npm account with publish access to `@ainumbers` must have two-factor auth set to "Authorization and writes" (npmjs.com → account Settings → Security). This can't be automated from the repo — it's a per-account setting on npmjs.com — but trusted-publishing OIDC (above) means CI itself never needs a token or 2FA prompt; the requirement only bites human `npm login` publishes, which this pipeline never does.

**Lockfile:** `package.json` at repo root has zero `dependencies` (site-repo-style zero-dep policy extends to helm/), and the published `@ainumbers/helm-cli` package's `postinstall` uses only Node builtins (`node:fs`, `node:crypto`, `node:path`, `fetch`) — no third-party runtime deps either. There is nothing for a lockfile to pin; `npm audit signatures` (documented in `docs/INSTALL.md`) covers the one dependency edge that does exist, npm's own registry signature over the published tarball.

## Offline distribution + D-SIGN-1 free hardening (HELM-P3-D8)

Every GA release ships, alongside the four SEA binaries and the DSSE-signed manifest:

- **`helm-cli-<version>.tgz`** — the filled npm package packed with `npm pack` (no install, no network — reads `package.json` + `files` only), so `npm install ./helm-cli-<version>.tgz` works with zero registry reachability. Byte-identical to what `publish-npm` would publish, since both are built from the same `dist/packaging/npm` output.
- **`SHA256SUMS`** — plain digests over every staged asset (binaries, tarball, manifests), for `sha256sum -c` verification with no repo code.
- **GitHub build provenance** via `actions/attest-build-provenance` (first-party, `v4.1.1` SHA-pinned — no SO #17 authorization needed, unlike `sigstore/cosign-installer` which stays out per `HELM-CODE-SIGNING-RESEARCH-2026-07-23.md` §5) — attests every `helmd-*` binary and the offline tarball back to this exact workflow run. Verify with `gh attestation verify <file> --repo PostOakLabs/ainumbers-helm`.

`docs/INSTALL.md` documents all three from the consumer side, plus the Artifactory-virtual-repo path for orgs that mirror npm through a proxy instead of allowing direct installs.

## Homebrew tap (D-SIGN-4)

`packaging/homebrew/helm.rb.template` is filled by `gen-packaging-manifests.mjs` same as the npm/winget manifests, but publishing it needs a **new public repo** (`ainumbers/homebrew-helm`, the tap convention) — that's SO #8 flag-and-wait territory (new public repos), not something this WU creates. **Manual step (Tim, one-time):** create `PostOakLabs/homebrew-helm` (or an `ainumbers` org tap repo matching `docs/INSTALL.md`'s `brew install ainumbers/helm/helm`), add a step or manual copy of the filled `Formula/helm.rb` from each release's `dist/packaging/homebrew/` output into that repo. Until then, `brew install ainumbers/helm/helm` in `docs/INSTALL.md` documents the intended path, not a live one — winget/npm/manual download all work today regardless.
