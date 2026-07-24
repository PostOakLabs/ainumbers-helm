import { test } from "node:test";
import assert from "node:assert/strict";
import { skewBannerHtml, isDismissed, dismiss } from "./version-skew.mjs";

test("skewBannerHtml: renders nothing when unchecked (offline/disabled)", () => {
  assert.equal(skewBannerHtml({ checked: false, reason: "unreachable: timeout" }), "");
  assert.equal(skewBannerHtml(null), "");
  assert.equal(skewBannerHtml(undefined), "");
});

test("skewBannerHtml: renders nothing when up to date", () => {
  assert.equal(skewBannerHtml({ checked: true, upToDate: true, currentVersion: "0.2.0", latestVersion: "0.2.0" }), "");
});

// This is the "one version back" case named in the WU's done line.
test("skewBannerHtml: renders a download prompt one version behind latest", () => {
  const html = skewBannerHtml({
    checked: true,
    upToDate: false,
    belowMinimumSupported: false,
    currentVersion: "0.1.0",
    latestVersion: "0.2.0",
    minimumSupportedVersion: "0.1.0",
    releaseUrl: "https://ainumbers.co/helm",
    notice: null,
  });
  assert.match(html, /v0\.1\.0/);
  assert.match(html, /v0\.2\.0/);
  assert.match(html, /href="https:\/\/ainumbers\.co\/helm"/);
  assert.match(html, /Download the new installer/);
  assert.match(html, /data-state="info"/);
});

test("skewBannerHtml: below-minimum-supported renders as urgent (warning)", () => {
  const html = skewBannerHtml({
    checked: true,
    upToDate: false,
    belowMinimumSupported: true,
    currentVersion: "0.1.0",
    latestVersion: "0.3.0",
    minimumSupportedVersion: "0.2.0",
    releaseUrl: "https://ainumbers.co/helm",
    notice: "0.1.x is no longer supported.",
  });
  assert.match(html, /data-state="warning"/);
  assert.match(html, /0\.1\.x is no longer supported\./);
});

function fakeStorage() {
  const store = new Map();
  return {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, v),
  };
}

test("dismiss: scoped to the specific latest version, reappears on a newer one", () => {
  const storage = fakeStorage();
  assert.equal(isDismissed("0.2.0", storage), false);
  dismiss("0.2.0", storage);
  assert.equal(isDismissed("0.2.0", storage), true);
  assert.equal(isDismissed("0.3.0", storage), false, "a newer latest version is a fresh notice");
});
