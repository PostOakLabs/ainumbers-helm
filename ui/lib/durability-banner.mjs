// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Pure banner-state logic for the browser journal (P3-D7 durability UX).
// Kept separate from DOM mounting so it's node:test-able without a browser;
// app.mjs/views call renderBannerHtml() and set innerHTML, same convention
// as the rest of ui/ (no framework, no build step).

export const BANNER = {
  NONE: "none",
  READ_ONLY_TAB: "read-only-tab", // another tab holds the writer lock
  NOT_DURABLE: "not-durable", // navigator.storage.persisted() === false
};

// Second-tab read-only banner takes priority — it means THIS tab literally
// cannot record anything, which is a stronger warning than "may be evicted."
export function bannerFor({ writerRole, durable }) {
  if (writerRole === "reader") return BANNER.READ_ONLY_TAB;
  if (durable === false) return BANNER.NOT_DURABLE;
  return BANNER.NONE;
}

export function renderBannerHtml(banner) {
  switch (banner) {
    // §14.3: this tab's work is silently not being recorded — role="alert",
    // not "status", so it interrupts rather than waits to be polled.
    case BANNER.READ_ONLY_TAB:
      return `<div class="durability-banner" data-state="warning" role="alert">Another Helm tab is recording this session, so nothing here is being saved. Close the other tab, or reload this page to take over recording.</div>`;
    case BANNER.NOT_DURABLE:
      return `<div class="durability-banner" data-state="warning" role="status">This browser might clear your run history without warning. Download the evidence file after each run so you keep a copy. <button type="button" id="durability-banner-download" class="secondary">Download evidence file</button></div>`;
    default:
      return "";
  }
}
