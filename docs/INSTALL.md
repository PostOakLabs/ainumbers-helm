# Installing Helm

`helmd` is a Node SEA (single-executable) binary — no runtime dependency,
loopback-only by default (D8). Pick one:

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

## Manual download

Download `helmd-<platform>-<arch>` (or `.exe` on Windows) from a
[GitHub release](https://github.com/PostOakLabs/ainumbers-helm/releases),
plus `release-manifest.json` and `release-manifest.dsse.json` from the same
release.

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
