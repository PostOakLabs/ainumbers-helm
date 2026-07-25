import test from "node:test";
import assert from "node:assert/strict";
import { bannerFor, renderBannerHtml, BANNER } from "./durability-banner.mjs";

test("bannerFor: reader role always wins, even when durable", () => {
  assert.equal(bannerFor({ writerRole: "reader", durable: true }), BANNER.READ_ONLY_TAB);
  assert.equal(bannerFor({ writerRole: "reader", durable: false }), BANNER.READ_ONLY_TAB);
});

test("bannerFor: writer + not durable -> not-durable banner", () => {
  assert.equal(bannerFor({ writerRole: "writer", durable: false }), BANNER.NOT_DURABLE);
});

test("bannerFor: writer + durable -> no banner", () => {
  assert.equal(bannerFor({ writerRole: "writer", durable: true }), BANNER.NONE);
});

test("renderBannerHtml: NONE renders empty string", () => {
  assert.equal(renderBannerHtml(BANNER.NONE), "");
});

test("renderBannerHtml: read-only tab is role=alert — the user's work is silently not being saved", () => {
  const html = renderBannerHtml(BANNER.READ_ONLY_TAB);
  assert.match(html, /role="alert"/);
  assert.match(html, /durability-banner/);
});

test("renderBannerHtml: not-durable is role=status and offers a download button", () => {
  const html = renderBannerHtml(BANNER.NOT_DURABLE);
  assert.match(html, /role="status"/);
  assert.match(html, /durability-banner/);
  assert.match(html, /id="durability-banner-download"/);
});
