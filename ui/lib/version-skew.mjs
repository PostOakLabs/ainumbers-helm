// Pure banner-state logic for daemon version skew (HELM-P4-J4). Kept
// separate from DOM mounting so it's node:test-able without a browser, same
// convention as durability-banner.mjs. The daemon does the actual version
// comparison (GET /version-check — server-side, unrestricted by the page's
// `connect-src 'self'` CSP); this module only turns that result into a
// dismissible one-click "download new installer" prompt. Never blocks
// anything — a checked:false (offline/airgapped/disabled) result renders
// nothing, same passive-notice contract as hub/version-check.mjs (D10).

export function skewBannerHtml(versionCheck) {
  if (!versionCheck || !versionCheck.checked || versionCheck.upToDate) return "";
  const urgent = versionCheck.belowMinimumSupported;
  const notice = versionCheck.notice ? ` ${versionCheck.notice}` : "";
  return `<div class="version-skew-banner" data-state="${urgent ? "warning" : "info"}" role="status">
    This daemon is running v${versionCheck.currentVersion}; v${versionCheck.latestVersion} is available.${notice}
    <a href="${versionCheck.releaseUrl}" target="_blank" rel="noopener" id="version-skew-download">Download the new installer</a>
    <button type="button" id="version-skew-dismiss" class="secondary">Dismiss</button>
  </div>`;
}

const DISMISSED_KEY = "helm.versionSkew.dismissedFor";

// Dismissal is scoped to the specific latest version being offered — a
// dismissed v0.2.0 notice reappears once v0.3.0 ships, rather than
// suppressing all future skew notices forever.
export function isDismissed(latestVersion, storage = localStorage) {
  return storage.getItem(DISMISSED_KEY) === latestVersion;
}

export function dismiss(latestVersion, storage = localStorage) {
  storage.setItem(DISMISSED_KEY, latestVersion);
}
