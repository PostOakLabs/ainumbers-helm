# IT deployment kit (Intune / MDM)

`docs/INSTALL.md` covers the individual-user install paths (winget,
Homebrew, npm, raw binary). This page is for IT/MDM administrators pushing
`helmd` to a fleet — no interactive user action, and no internet access
required at install time. Scripts live in `packaging/it-deployment/`.

Helm ships as a Node SEA (single-executable) binary — there is no separate
Node runtime to bundle or manage. "Offline" here means the deployment
payload carries the binary itself; nothing is fetched during install.

## Windows: Intune Win32 app

1. Download a release from
   [GitHub Releases](https://github.com/PostOakLabs/ainumbers-helm/releases):
   `helmd-windows-x64.exe`, `SHA256SUMS`, `release-manifest.json`.
2. Stage a folder with those three files plus
   `packaging/it-deployment/install.ps1`, `detect.ps1`, and `uninstall.ps1`.
3. Package it as a `.intunewin` with the
   [Microsoft Win32 Content Prep Tool](https://learn.microsoft.com/mem/intune/apps/apps-win32-prepare)
   (`IntuneWinAppUtil.exe`), source folder = the staged folder, setup file =
   `install.ps1`.
4. Create the Win32 app in Intune:
   - **Install command:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1`
   - **Uninstall command:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1`
   - **Install behavior:** **User** (not System) — `helmd` autostart and the
     first-run pairing tab are per-user; a System-context install writes the
     LaunchAgent/Run-key equivalent for the wrong (or no) profile.
   - **Detection rule:** Custom script → `detect.ps1`. It checks a
     `version.txt` file `install.ps1` writes next to the binary (sourced
     from the signed `release-manifest.json`, not by launching the just
     -installed exe) — bump `$MinVersion` inside `detect.ps1` to force
     redeployment on an upgrade push.
5. Assign to the target device/user group.

`install.ps1` verifies `helmd-windows-x64.exe`'s SHA-256 against the shipped
`SHA256SUMS` before copying it anywhere (same plain-text checksum file
`docs/INSTALL.md` documents as the no-Node-required verification path) and
refuses to install on a mismatch. It then launches `helmd.exe start` once,
which is the *same* first-run path an interactive install takes — it opens
the pairing tab and writes the HKCU `Run` autostart entry (`hub/autostart.mjs`,
HELM-P4-J4). Nothing here duplicates or diverges from that logic.

## macOS: unsigned component pkg (Jamf / Kandji / any MDM)

Apple Developer ID code signing is deferred (D-SIGN-2/3 —
`HELM-CODE-SIGNING-RESEARCH-2026-07-23.md` §6), the same reason the raw SEA
binary download in `docs/INSTALL.md` is unsigned. `packaging/it-deployment/build-pkg.sh`
wraps a downloaded, hash-verified `helmd-macos-<arch>` binary into a
`pkgbuild` component package with a postinstall script:

```
./packaging/it-deployment/build-pkg.sh /path/to/helmd-macos-arm64 1.2.3
```

This produces `AINumbersHelm-1.2.3-unsigned.pkg`. The postinstall script
copies the binary to `/usr/local/bin/helmd` and — using the *console* user,
not root, since Jamf/`sudo installer` policy runs execute as root and
`$HOME` under root is not the logged-in user's home — launches `helmd start`
once to trigger the same first-run LaunchAgent write J4 ships interactively.

**Gatekeeper note, read before distributing:** an unsigned `.pkg`
double-clicked by an end user is blocked by Gatekeeper (no Developer ID,
same posture as the raw `.exe`) — do not hand this file to end users
directly. **A Jamf (or equivalent MDM) *policy* install is not a
double-click; it invokes `installer(8)` directly via the MDM agent, which
bypasses the Gatekeeper quarantine-attribute check entirely** (MDM enrollment
is itself the trust boundary Apple substitutes for a Developer ID signature
in a managed-install flow). This is the intended distribution path for this
pkg — build it, upload it to your MDM's software repository, and scope a
policy to install it. It is not a general-purpose downloadable installer.

## `#load=<url>` — opening a shared bundle link directly

For SharePoint/Teams "share a link" workflows: host an evidence bundle
`.json` at any `https://` URL your recipients can reach (SharePoint direct
download link, an intranet file share over HTTPS, etc.) and share a link of
the shape:

```
https://<helm-app-host>/#load=<url-encoded-https-bundle-url>
```

Opening that link lands straight on the Verify view with the bundle
pre-fetched — no file picker, no daemon pairing required (Verify is fully
client-side; a recipient without `helmd` installed or paired at all can
still open the link and see the bundle). They still need to load the
producer's public-key/identity JSON separately — Helm has no key registry,
the same out-of-band requirement `docs/INSTALL.md`'s verify-by-hand section
documents.

The URL must be `https://` (no `file://`, no `javascript:`); an unreachable
host, non-200 response, or non-JSON body fails gracefully with an inline
error, same doctrine as the `?config=` company-profile fetch (`ui/lib/company-profile.mjs`,
HELM-P4-J1) — this reuses that feature's already-widened
`connect-src 'self' https:` CSP, not a separate exception.
