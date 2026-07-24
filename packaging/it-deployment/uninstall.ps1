<#
.SYNOPSIS
  HELM-P4-J5: Intune Win32-app uninstall script for helmd.

.DESCRIPTION
  Runs `helmd.exe uninstall` first (removes the HKCU Run-key autostart entry
  — Zoom-orphan lesson, P3 robustness #8: never leave an autostart entry
  pointing at a binary about to be deleted), then removes the install
  directory. Never touches ~/.helm state (journal/keys/config) — same
  deliberate scope as the interactive `helmd uninstall` command.
#>
$ErrorActionPreference = "Continue"

$InstallDir = Join-Path $env:LOCALAPPDATA "Helm"
$InstalledExe = Join-Path $InstallDir "helmd.exe"

if (Test-Path $InstalledExe) {
  & $InstalledExe uninstall
}

if (Test-Path $InstallDir) {
  Remove-Item -Path $InstallDir -Recurse -Force
}

exit 0
