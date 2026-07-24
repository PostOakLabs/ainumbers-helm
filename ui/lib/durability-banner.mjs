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
    case BANNER.READ_ONLY_TAB:
      return `<div class="durability-banner" data-state="warning" role="status">Another tab is recording this session — this tab is read-only. Close the other tab or reload here to take over.</div>`;
    case BANNER.NOT_DURABLE:
      return `<div class="durability-banner" data-state="warning" role="status">Not durable here — export the evidence bundle after each run, or install the Helm engine for durable storage.</div>`;
    default:
      return "";
  }
}
