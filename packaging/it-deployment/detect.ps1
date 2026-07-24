<#
.SYNOPSIS
  HELM-P4-J5: Intune Win32-app detection script for helmd.

.DESCRIPTION
  Intune's "script" detection method runs this and reads ONLY the exit code
  (0 = installed/compliant, non-zero = not installed) — stdout is ignored
  unless you configure a registry/MSI detection instead, which doesn't apply
  here (per-user file install, no registry key, no MSI). This checks the
  version-file install.ps1 writes rather than launching helmd.exe, so
  detection never depends on the daemon's runtime behavior or exit codes.

  Set $MinVersion below to gate re-deployment on an upgrade (Intune re-runs
  install.ps1 automatically once detection starts failing for machines on an
  older version). Leave "0.0.0" to only check presence, not version.
#>

$MinVersion = "0.0.0"

$InstallDir = Join-Path $env:LOCALAPPDATA "Helm"
$InstalledExe = Join-Path $InstallDir "helmd.exe"
$VersionFile = Join-Path $InstallDir "version.txt"

if (-not (Test-Path $InstalledExe)) { exit 1 }
if (-not (Test-Path $VersionFile)) { exit 1 }

$Installed = (Get-Content -Path $VersionFile -Raw).Trim()

try {
  $InstalledV = [version]($Installed -replace '[^0-9.].*$', '')
  $MinV = [version]$MinVersion
} catch {
  # Unparseable version string (shouldn't happen — install.ps1 writes it
  # verbatim from the signed manifest) — treat as not-compliant, safer than
  # silently passing detection on garbage data.
  exit 1
}

if ($InstalledV -ge $MinV) { exit 0 } else { exit 1 }
