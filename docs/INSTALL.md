# Installing Helm

`helmd` is a Node SEA (single-executable) binary — no runtime dependency,
loopback-only by default (D8). Pick one:

Deploying to a managed fleet instead of installing by hand? See
[IT-DEPLOYMENT.md](IT-DEPLOYMENT.md) (Intune Win32 app, MDM `.pkg`).

## winget (Windows)

```
winget install AINumbers.Helm
```

## Homebrew (macOS)

```
brew install ainumbers/helm/helm
```

## npm (any platform with Node ≥22.5)

```
npm install -g @ainumbers/helm-cli
```

Installs `helmd` on PATH. The postinstall step downloads the platform binary
from the matching [GitHub release](https://github.com/PostOakLabs/ainumbers-helm/releases)
and verifies its SHA-256 against the value baked in from the signed release
manifest before use — install aborts on any mismatch.

## Offline install (no npm registry access)

Banks and other locked-down environments often block `registry.npmjs.org`
outright. Download `helm-cli-<version>.tgz` from a
[GitHub release](https://github.com/PostOakLabs/ainumbers-helm/releases) and
install it directly — no registry reachability required:

```
npm install ./helm-cli-<version>.tgz
```

It is packed from the exact same filled package `npm publish` would ship
(real sha256 values baked in), so behavior is identical to the registry
install. If your org mirrors npm through an internal proxy (Artifactory,
Nexus, etc.), push the tarball into your virtual npm repo instead of
installing it locally and consume it from there like any other package.

## Advanced: raw SEA binary download

Only reach for this if none of winget/Homebrew/npm fit (e.g. scripting a CI
image). Download `helmd-<platform>-<arch>` (or `.exe` on Windows) from a
[GitHub release](https://github.com/PostOakLabs/ainumbers-helm/releases),
plus `release-manifest.json`, `release-manifest.dsse.json`, and
`SHA256SUMS` from the same release.

**Honest note on Windows SmartScreen / Defender:** the raw `helmd.exe` is
**not code-signed** (D-SIGN-2/3, Azure Trusted Signing, is deferred — see
`HELM-CODE-SIGNING-RESEARCH-2026-07-23.md` §6). An unsigned single-executable
binary is commonly flagged by Defender/SmartScreen on first run (this pattern
was actively abused by the Oct 2025 "Stealit" campaign, so the caution is
warranted, not just noise). We will not ask you to click through that
warning — if your system blocks it, prefer winget/Homebrew/npm above (all
three sidestep Mark-of-the-Web) or wait for a signed release.

## Verifying a downloaded release by hand

Every tagged release is a DSSE/in-toto statement dual-signed (Ed25519 +
ML-DSA-44, RFC 9964) by the AINumbers Helm release key (public half committed
at `schema/release-signing-keys.json`, D10). To verify offline against the
files you downloaded:

```
node scripts/verify-release-manifest.mjs /path/to/downloaded/release/dir
```

This checks: (1) both signature families over the manifest verify against
the committed public key, (2) every artifact's SHA-256 on disk matches the
digest the release key attested to. A tampered binary or a manifest signed
by any other key fails closed.

Two lighter-weight alternatives ship alongside the DSSE manifest, for
verifiers who don't want to run repo code:

- **`SHA256SUMS`** — plain-text digests, checkable with coreutils alone:
  `sha256sum -c SHA256SUMS` (run from the directory holding the downloaded
  files).
- **GitHub build provenance** (D-SIGN-1, `actions/attest-build-provenance`,
  free/first-party, no third-party action) — attests each binary and the
  offline npm tarball were built by this repo's `release.yml`, from this
  exact source, with no way to forge it after the fact:
  `gh attestation verify helmd-linux-x64 --repo PostOakLabs/ainumbers-helm`
  (works for any of the `helmd-*` binaries or `helm-cli-*.tgz`).

npm installs additionally support `npm audit signatures`, which checks the
installed package's registry signature against npm's public key — run it
after any `npm install -g @ainumbers/helm-cli` or local tarball install to
confirm nothing was tampered with in transit.

## First run

```
helmd start
```

`helmd` serves its own UI at `http://127.0.0.1:<port>/` (default port 4173)
— no separate download, no `file://` page. On first run it opens your
default browser at that URL, pre-paired with a one-time token in the
fragment (`#token=...`, stripped from the address bar immediately, never
sent to the server). If nothing opens (headless box, no default browser)
copy the printed URL yourself. Later starts stay silent; run `helmd start
--open` to force the browser open again.

## After installing

```
helmd doctor
```

Runs the same self-check the daemon runs on start: config readable, token
file mode 0600 (POSIX), loopback port free, journal replay-integrity (if a
prior install left state), and a passive version-check notice (never an
auto-update — see below).

## Updates

Helm does **not** auto-update (D10 — decided, not a gap: a control-plane
daemon silently replacing its own binary is a supply-chain risk we chose not
to take in Phase 1). `helmd doctor` and normal operation both poll a static
version-check endpoint and print a notice when a newer release exists; you
update the same way you installed (`winget upgrade`, `brew upgrade`, `npm
update -g`, or a fresh manual download + `verify-release-manifest.mjs`).

Set `versionCheckUrl` to `""` in `~/.helm/config.json` to disable the check
entirely (airgapped installs).
