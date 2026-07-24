<#
.SYNOPSIS
  HELM-P4-J5: Intune Win32-app install script for helmd (offline, no network
  access required at install time — the payload ships the binary itself).

.DESCRIPTION
  Copies the pre-verified helmd-windows-x64.exe payload to a per-user install
  directory and launches it once to trigger the SAME first-run path a normal
  interactive install goes through (opens the pairing tab, writes the HKCU
  Run-key autostart entry — see hub/autostart.mjs, HELM-P4-J4). This script
  does not duplicate that logic; it just gets the binary onto disk and runs
  it once as the logged-in user.

  Per-user, no admin rights required — matches helmd's own install model
  (winget/Homebrew/npm are all per-user too). Deploy this as an Intune Win32
  app in "install for user" (not device/SYSTEM) context, or the first-run
  browser launch and HKCU Run key land in the wrong profile.

  PowerShell 5.1-safe by construction: no `??`, no ternary, no classes.

.PARAMETER PayloadDir
  Directory holding this script's siblings: helmd-windows-x64.exe,
  SHA256SUMS, and release-manifest.json (all three ship together in every
  GitHub release, per docs/RELEASING.md). Defaults to the script's own
  directory, which is how Intune stages a Win32 app (.intunewin) —
  everything extracts to one folder and runs `install.ps1` from inside it.

.NOTES
  Verification is SHA-256 only (PowerShell-native `Get-FileHash`), the same
  "lighter-weight alternative" docs/INSTALL.md documents for verifiers who
  don't want to run repo code — no Node runtime is required or bundled here,
  because helmd itself is a Node SEA (single-executable) binary with no
  runtime dependency; there is nothing to bundle.
#>
[CmdletBinding()]
param(
  [string]$PayloadDir = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Helm"
$BinaryName = "helmd-windows-x64.exe"
$InstalledExe = Join-Path $InstallDir "helmd.exe"
$VersionFile = Join-Path $InstallDir "version.txt"

function Write-Log($msg) {
  Write-Output ("[helm-install] {0}" -f $msg)
}

$SourceExe = Join-Path $PayloadDir $BinaryName
$SumsFile = Join-Path $PayloadDir "SHA256SUMS"
$ManifestFile = Join-Path $PayloadDir "release-manifest.json"

if (-not (Test-Path $SourceExe)) {
  throw "Payload missing: $SourceExe not found next to install.ps1. Stage the .intunewin with helmd-windows-x64.exe + SHA256SUMS + release-manifest.json alongside this script."
}
if (-not (Test-Path $SumsFile)) {
  throw "Payload missing: SHA256SUMS not found next to install.ps1. Every offline deployment kit ships its own checksums — do not skip verification."
}
if (-not (Test-Path $ManifestFile)) {
  throw "Payload missing: release-manifest.json not found next to install.ps1 (needed for the version-file detection rule)."
}

# SHA256SUMS is the plain `sha256sum`-format file docs/INSTALL.md ships
# alongside every release (two spaces between hash and filename, forward
# slashes possible). Match by filename, not line position.
$ExpectedLine = Select-String -Path $SumsFile -Pattern ([regex]::Escape($BinaryName)) | Select-Object -First 1
if (-not $ExpectedLine) {
  throw "SHA256SUMS has no entry for $BinaryName — refusing to install an unverifiable binary."
}
$ExpectedHash = ($ExpectedLine.Line -split '\s+')[0].ToUpperInvariant()
$ActualHash = (Get-FileHash -Path $SourceExe -Algorithm SHA256).Hash.ToUpperInvariant()
if ($ActualHash -ne $ExpectedHash) {
  throw "SHA-256 mismatch for $BinaryName - expected $ExpectedHash, got $ActualHash. Payload is corrupt or tampered; install aborted."
}
Write-Log "SHA-256 verified: $BinaryName"

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path $SourceExe -Destination $InstalledExe -Force
Write-Log "Installed to $InstalledExe"

# Version-file detection rule (for the companion Intune "detect.ps1" — see
# docs/IT-DEPLOYMENT.md): read the version straight out of the signed
# release-manifest.json's predicate rather than launching the just-installed
# binary — no dependency on an exit code or stdout shape from helmd itself.
$ManifestJson = Get-Content -Path $ManifestFile -Raw | ConvertFrom-Json
$Version = $ManifestJson.predicate.version
if (-not $Version) {
  throw "release-manifest.json has no predicate.version field — cannot write the detection version-file."
}
Set-Content -Path $VersionFile -Value $Version -Encoding ascii
Write-Log ("Version file written: {0}" -f $Version)

# First run: same path an interactive install takes (opens the pairing tab,
# writes the HKCU Run-key autostart entry via hub/autostart.mjs). Detached
# so the Intune install context (which may not stay attached to a foreground
# session) doesn't block on it; `start` daemonizes itself already.
Write-Log "Launching first run (installs autostart, opens pairing tab)..."
Start-Process -FilePath $InstalledExe -ArgumentList "start" -WindowStyle Hidden

Write-Log "Install complete."
exit 0
