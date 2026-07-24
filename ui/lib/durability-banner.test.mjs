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

test("renderBannerHtml: known banners render a role=status element", () => {
  for (const b of [BANNER.READ_ONLY_TAB, BANNER.NOT_DURABLE]) {
    const html = renderBannerHtml(b);
    assert.match(html, /role="status"/);
    assert.match(html, /durability-banner/);
  }
});
