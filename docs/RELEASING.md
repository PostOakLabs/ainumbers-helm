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

## Merge flow

1. Land normal feature/fix PRs against `main` with Conventional-Commit titles.
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
