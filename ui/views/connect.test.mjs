// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// connectorCard is daemon-data-in, HTML-string-out — the JSON.stringify'd
// contract dumped into a <pre> (HELM-UX-BUILD-SPEC.md §16.2) is the reliable
// breakout vector since JSON.stringify never escapes "<". Regression cover
// for HELM-UX2-A-ESC.
import { test } from "node:test";
import assert from "node:assert/strict";
import { connectorCard } from "./connect.mjs";

const HOSTILE = '</pre><img src=x onerror=alert(document.domain)>';

test("connectorCard: hostile contract fields never reach the DOM unescaped", () => {
  const entry = {
    status: `connected" onmouseover="alert(1)`,
    expiry: HOSTILE,
    contract: {
      connector_id: `x"><script>alert(1)</script>`,
      name: HOSTILE,
      publisher: HOSTILE,
      connector_version: HOSTILE,
      allowed_hosts: [HOSTILE],
      allowed_methods: [HOSTILE],
      scopes: [HOSTILE],
      vault_scope: [HOSTILE],
    },
  };

  const html = connectorCard(entry);

  assert.ok(!html.includes("<script>"), "raw <script> tag leaked into markup");
  assert.ok(!html.includes("<img"), "raw <img> tag leaked into markup");
  assert.ok(!html.includes('onmouseover="alert'), "raw attribute-breakout leaked into markup");
  // the full-JSON <pre> block is the vector the row calls out explicitly —
  // confirm the escaped form is present instead of a raw "</pre>" mid-string.
  assert.ok(html.includes("&lt;/pre&gt;"), "JSON.stringify'd contract's </pre> was not escaped");
});

test("connectorCard: well-formed contract still renders its fields", () => {
  const html = connectorCard({
    status: "connected",
    expiry: "2027-01-01",
    contract: {
      connector_id: "google-drive.fetch",
      name: "Google Drive",
      publisher: "Post Oak Labs",
      connector_version: "1",
      allowed_hosts: ["www.googleapis.com"],
      allowed_methods: ["GET"],
      scopes: ["drive.file"],
      vault_scope: ["drive.file"],
    },
  });
  assert.ok(html.includes("Google Drive"));
  assert.ok(html.includes("www.googleapis.com"));
  assert.ok(html.includes("connected"));
});
