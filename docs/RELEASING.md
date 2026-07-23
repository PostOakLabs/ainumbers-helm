# Releasing

Releases are automated by [release-please](https://github.com/googleapis/release-please) (`.github/workflows/release-please.yml`, SHA-pinned per SO #17 — the only third-party action in this program).

## How it works

1. Every push to `main` runs release-please. It reads squash-merge PR titles since the last release, parsed as [Conventional Commits](https://www.conventionalcommits.org/), and keeps a standing **release PR** up to date with the computed next version + `CHANGELOG.md` entry.
2. Merging that PR (squash, into `main`) makes release-please create the `vN.N.N` tag and a GitHub Release.
3. The tag push triggers the existing `.github/workflows/release.yml` pipeline: three-platform SEA build, signed release manifest, packaging manifests, published as a GitHub pre-release.

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
3. When ready to cut a release, review and squash-merge the release PR. That's the only manual step.
