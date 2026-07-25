# Releasing

Releases are CalVer, tagged by hand (HELM-CALVER-1, 2026-07-25): the version
IS the ship date, `YYYY.M.D`, no zero-padding, no `v` prefix — three numeric
components so npm accepts it unchanged. There is no support window, no
deprecation policy and no dependent to protect with a computed major/minor/
patch bump, so nothing computes one.

## Cutting a release

1. Bump the `version` field in root `package.json` to the exact tag string
   (e.g. `"2026.7.25"`) and merge that to `main` first —
   `scripts/release-manifest.mjs` refuses to sign the release if the tag and
   `package.json` don't match, by design (a mismatched version is a
   mislabeled release, not a warning).
2. Tag and push:

```
git tag 2026.7.25 && git push --tags
```

No release PR, no changelog ritual beyond step 1. The tag push triggers
`.github/workflows/release.yml`: four-platform SEA build → signed release
manifest → verify (fail-closed) → GitHub release (GA tags self-promote to
`latest`) → `publish-version-feed` → `publish-npm` (GA tags only).

⚠ **Step 1 is not optional and is easy to skip.** `release-manifest.mjs`
compares the tag against `package.json` and refuses to sign a mismatch — so
forgetting it fails the run *after* the build, with the tag already pushed.
Because CalVer names the tag after the date, recovering means deleting and
re-pushing the same tag rather than picking a new number. This happened on
the first CalVer release (2026-07-25). The planned automated tagger folds
the bump into the same step that computes the tag, so the two can no longer
drift apart.

The `release` Environment previously paused here for an approval click. That
gate was removed 2026-07-25 (Tim): with no users, a signing job that waits on
a human is friction rather than protection, and the reviewer was
self-approvable and admin-bypassable anyway. Revisit when Helm has users or
when npm publishing is re-enabled — an npm version publish is irreversible in
a way a GitHub release is not.

An `-rc` suffix (`2026.7.25-rc1`) stays a GitHub prerelease and never
publishes to npm.

`v0.1.0` (the last semver release, tagged before this change) stays tagged
and published as-is — it is not retagged or rewritten. The first CalVer tag
is simply the next release.

## npm publishing (GA releases only)

GA tags publish `@ainumbers/helm-cli` to npm via the `publish-npm` job in
`release.yml`. It uses **OIDC trusted publishing** — no npm token lives in
this repo. The npm package (`packaging/npm/`) is a thin launcher:
`postinstall` downloads the platform-matched `helmd` SEA binary from the
matching GitHub release and verifies it against a sha256 baked in from the
signed release manifest at build time (HELM-H8) — no source is trusted at
install time beyond that pinned digest.

**Deferred (HELM-REL-NPM-DEFER, 2026-07-23):** `publish-npm` is gated behind
repo variable `vars.NPM_PUBLISH_ENABLED` (default unset/false), so it skips
cleanly instead of red-failing — npm has no way to attach a trusted
publisher to a package that doesn't exist yet, and the signed GitHub release
stands on its own for GA. **Revive trigger:** once the npm trusted publisher
is attached (below) via a one-time bootstrap publish, set
`vars.NPM_PUBLISH_ENABLED = 'true'` in repo settings → Variables. No
workflow change needed — OIDC wiring is already in place.

### One-time setup (Tim, manual — cannot be automated from this repo)

Trusted publishing is configured on the **npm side**, once, after the repo
goes public:

1. Sign in to npmjs.com, go to the `@ainumbers/helm-cli` package's
   **Settings → Trusted Publisher** (or create the package first — first
   publish under a trusted publisher can also be done via a one-time
   classic token, see npm's trusted-publishing docs for the bootstrap
   path).
2. Add a GitHub Actions trusted publisher:
   - **Organization/repo:** `PostOakLabs/ainumbers-helm`
   - **Workflow filename:** `release.yml`
   - **Environment:** `release`
3. No token is stored anywhere — the `publish-npm` job's `id-token: write`
   permission lets npm verify the run's OIDC identity against this config
   at publish time.

Until this is configured AND `vars.NPM_PUBLISH_ENABLED` is flipped to
`'true'`, `publish-npm` skips on every GA release — the GitHub release
itself is unaffected since it publishes in the job before `publish-npm`.

**2FA on the npm side (Tim, manual, one-time):** every npm account with
publish access to `@ainumbers` must have two-factor auth set to
"Authorization and writes" (npmjs.com → account Settings → Security). This
can't be automated from the repo — it's a per-account setting on npmjs.com
— but trusted-publishing OIDC (above) means CI itself never needs a token
or 2FA prompt; the requirement only bites human `npm login` publishes,
which this pipeline never does.

**Lockfile:** `package.json` at repo root has zero `dependencies`
(site-repo-style zero-dep policy extends to helm/), and the published
`@ainumbers/helm-cli` package's `postinstall` uses only Node builtins
(`node:fs`, `node:crypto`, `node:path`, `fetch`) — no third-party runtime
deps either. There is nothing for a lockfile to pin; `npm audit signatures`
(documented in `docs/INSTALL.md`) covers the one dependency edge that does
exist, npm's own registry signature over the published tarball.

## Offline distribution + D-SIGN-1 free hardening (HELM-P3-D8)

Every GA release ships, alongside the four SEA binaries and the DSSE-signed
manifest:

- **`helm-cli-<version>.tgz`** — the filled npm package packed with
  `npm pack` (no install, no network — reads `package.json` + `files`
  only), so `npm install ./helm-cli-<version>.tgz` works with zero registry
  reachability. Byte-identical to what `publish-npm` would publish, since
  both are built from the same `dist/packaging/npm` output.
- **`SHA256SUMS`** — plain digests over every staged asset (binaries,
  tarball, manifests), for `sha256sum -c` verification with no repo code.
- **GitHub build provenance** via `actions/attest-build-provenance`
  (first-party, `v4.1.1` SHA-pinned — no extra third-party-action review
  needed, unlike `sigstore/cosign-installer` which stays out per
  `HELM-CODE-SIGNING-RESEARCH-2026-07-23.md` §5) — attests every `helmd-*`
  binary and the offline tarball back to this exact workflow run. Verify
  with `gh attestation verify <file> --repo PostOakLabs/ainumbers-helm`.

`docs/INSTALL.md` documents all three from the consumer side, plus the
Artifactory-virtual-repo path for orgs that mirror npm through a proxy
instead of allowing direct installs.

## Homebrew tap (D-SIGN-4)

`packaging/homebrew/helm.rb.template` is filled by
`gen-packaging-manifests.mjs` same as the npm/winget manifests, but
publishing it needs a **new public repo** (`ainumbers/homebrew-helm`, the
tap convention) — creating a new public repo is a deliberate, one-time act,
not something automated tooling should do on its own. **Manual step,
one-time:** create `PostOakLabs/homebrew-helm` (or an `ainumbers` org tap
repo matching `docs/INSTALL.md`'s `brew install ainumbers/helm/helm`), add
a step or manual copy of the filled `Formula/helm.rb` from each release's
`dist/packaging/homebrew/` output into that repo. Until then,
`brew install ainumbers/helm/helm` in `docs/INSTALL.md` documents the
intended path, not a live one — winget/npm/manual download all work today
regardless.
