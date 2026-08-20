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

## Running from a repo clone (developers)

The [`ainumbers-helm`](https://github.com/PostOakLabs/ainumbers-helm) repo
itself declares a `bin` entry (`package.json` → `bin.helmd`), so a clone
gives you `helmd` without any of the packaging above:

```
git clone https://github.com/PostOakLabs/ainumbers-helm.git
cd ainumbers-helm
npm install -g .
helmd doctor
```

or, without installing anything globally:

```
node bin/helmd.mjs doctor
```

`bin/helmd.mjs` is a thin wrapper: `start`/`stop`/`status`/`open`/`uninstall`
are forwarded straight to `hub/index.mjs` (the same daemon entrypoint this
guide's other install methods run); `doctor` calls the self-check directly
so it can offer `--json`; `export-bpmn <workflow_id> [out.bpmn]` wraps
`scripts/export-bpmn.mjs` to write a compiled pack's workflow as BPMN 2.0
XML. It adds no runtime dependency — `npm install -g .` has nothing to
fetch.

### CLI stability contract

- **Stable:** the command names (`start`, `stop`, `status`, `doctor`, `open`,
  `uninstall`, `export-bpmn`), their plain-text output, and their exit codes
  (`0` success; a subcommand's own failure code is passed through unchanged;
  an unknown command is a usage error and exits `2`). Script against these.
- **Provisional:** `--json` output shapes (currently only `doctor --json`).
  These may change without a major-version bump until this notice is
  removed. Don't parse them in anything you can't update on short notice.

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
— no separate download, no `file://` page. Every `helmd start` opens your
default browser at that URL, pre-paired with a one-time token in the
fragment (`#token=...`, stripped from the address bar immediately, never
sent to the server). If nothing opens (headless box, no default browser,
or the auto-open step failed) the URL is also printed to the console —
copy/paste it yourself; it's always a working fallback, never required.

**Installing Helm does not start it.** winget/Homebrew/npm all just place
the binary; nothing about the install itself launches the daemon. Run
`helmd start` (then `helmd open` if you need the pairing link again), or
double-click the Start Menu shortcut (Windows, if you added one, below).
Skip both and the UI never loads, and it will look like nothing happened.
And once it's up, Helm auto-stops after 120 seconds idle (no open UI tab,
no in-flight run) unless you turn on **Start Helm when I sign in** on the
Operate tab's autostart switch, so a Helm you started once and walked away
from will need `helmd start` again next time. That's expected.

### A Start Menu shortcut, if you ask for one (Windows)

Ticking **Add a Helm shortcut to this computer** on the **Operate** tab adds
**Helm** to your Start Menu, at
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Helm.lnk`. Untick it, or run
`helmd uninstall`, to remove it. Like autostart, it used to be created on
first run without asking, and is now off by default.

This exists because `winget install` alone leaves nothing to click: winget's
`portable` installer type drops the binary and adds a PATH alias, and cannot
create a Start Menu or desktop entry at any setting. Creating the shortcut
from the daemon instead means npm and raw-binary installs get it too.

The shortcut targets the `helmd` binary, never a URL — a shortcut carrying a
pairing link would store a long-lived token in an unprotected file and reuse
it on every launch. Launching it starts the daemon, which mints a fresh link.

macOS and Linux get no shortcut yet (they need a `.app` bundle and a
`.desktop` entry respectively); `helmd status` reports this honestly rather
than claiming one exists.

### Autostart is off until you turn it on

Helm does not add itself to your startup items. Nothing about installing or
running it writes a login entry — that only happens when you tick **Start Helm
when I sign in** on the **Operate** tab.

Earlier versions installed the entry on first run and printed a note about it
to the console. That note was unreadable in the case it mattered most (a
double-clicked download closes its console window), so what it amounted to was
persistence installed without consent. It is opt-in now, on every platform.

When you do turn it on, it is per-user only — no administrator rights, nothing
written outside your own account:

| Platform | What is written |
|---|---|
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AINumbersHelmd` |
| macOS | `~/Library/LaunchAgents/co.ainumbers.helmd.plist` (visible in System Settings → Login Items) |
| Linux | nothing — no autostart entry is available yet |

Untick the box to remove it, or run `helmd uninstall` (below). The macOS agent
sets `RunAtLoad` but **not** `KeepAlive`, so helmd starts when you log in and
stays stopped when you stop it.

The same tab has a second, independent box for a Start Menu shortcut, also off
by default.

`helmd status` and `helmd doctor` both check that the entry still points at a
Helm that exists. Moving or re-downloading the binary leaves the recorded path
behind, and an entry pointing at a file that is gone fails silently at every
sign-in — both commands now say so instead of reporting it as installed and
healthy. Turn the box off and on again to rewrite it with the current path.

## Starting, stopping, and removing Helm

helmd is a background process. It has no window, no tray icon and no taskbar
entry, so these are the commands that control it:

```
helmd status
```

Reports whether the daemon is running, on which port, its version, and
whether the autostart entry is installed. Exits non-zero when it is not
running, so scripts can branch on it.

```
helmd stop
```

Stops the running daemon. Your data is untouched — this only ends the
process. Open Helm again when you need it; it comes back at your next sign-in
only if you turned autostart on. Stopping an already-stopped daemon is not an
error.

```
helmd open
```

Asks an already-running daemon for a fresh pairing link and opens it. Use
this when you have closed the tab.

```
helmd uninstall
```

Removes the autostart entry and shortcut described above if you enabled them,
and nothing else. Your
`~/.helm` state — journal, keys, config — is deliberately left in place;
delete that directory yourself if you also want the data gone.

## After installing

```
helmd doctor
```

Runs the same self-check the daemon runs on start: config readable, token
file mode 0600 (POSIX), the loopback port either free or held by your own
helmd, journal replay-integrity (if a prior install left state), and a
passive version-check notice (never an auto-update — see below).

`helmd doctor` is safe to run while helmd is running — it identifies the
listener on the port rather than assuming an occupied port is a problem.
Add `--json` for a machine-readable `{ok, checks: [...]}` (see the
stability contract above — the `--json` shape is provisional, the plain
output and exit code are not).

```
helmd export-bpmn <workflow_id> [out.bpmn]
```

Exports a compiled pack's workflow as BPMN 2.0 XML — to stdout, or to
`out.bpmn` if given. Exits non-zero with a message on stderr for an unknown
`workflow_id`.

## Updates

Helm does **not** auto-update (D10 — decided, not a gap: a control-plane
daemon silently replacing its own binary is a supply-chain risk we chose not
to take in Phase 1). `helmd doctor` and normal operation both poll a static
version-check endpoint and print a notice when a newer release exists; you
update the same way you installed (`winget upgrade`, `brew upgrade`, `npm
update -g`, or a fresh manual download + `verify-release-manifest.mjs`).

Set `versionCheckUrl` to `""` in `~/.helm/config.json` to disable the check
entirely (airgapped installs).
