// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Regression cover for HELM-UX-BUILD-SPEC.md §19.3's three prohibitions and
// §19.5.4's evidence.export tier separation — the specific content this row
// exists to get right, not just "does it render".
import { test } from "node:test";
import assert from "node:assert/strict";
import { agentsContentHtml } from "./agents.mjs";

test("agentsContentHtml: no copy-to-clipboard control for the bearer token", () => {
  const html = agentsContentHtml({ port: 4173 });
  assert.ok(!html.includes("navigator.clipboard"), "no clipboard API reference");
  assert.ok(!html.includes("<button"), "no button controls at all on this static content view");
  assert.ok(html.includes("no copy-to-clipboard button"), "must explicitly disclaim the copy-to-clipboard flow, not just omit it silently");
});

test("agentsContentHtml: no connector-authorization path", () => {
  const html = agentsContentHtml({ port: 4173 });
  assert.ok(!/connector.authorize/i.test(html), "no connector.authorize tool or path referenced as callable here");
  assert.ok(html.includes("always happens in this UI, never over MCP"), "must state consent stays in the UI");
});

test("agentsContentHtml: never presents this tab as a route to mcp.ainumbers.co", () => {
  const html = agentsContentHtml({ port: 4173 });
  assert.ok(html.includes("mcp.ainumbers.co"), "the hosted server should be named only to disclaim it");
  assert.ok(html.includes("No route to"), "must state explicitly there is no route to the hosted server");
  assert.ok(!/href="[^"]*mcp\.ainumbers\.co/i.test(html), "must never link to the hosted server");
});

test("agentsContentHtml: evidence.export is never listed as a peer of the read/run tools", () => {
  const html = agentsContentHtml({ port: 4173 });
  const toolsSectionStart = html.indexOf('id="agents-tools-heading"');
  const evidenceSectionStart = html.indexOf('id="agents-evidence-heading"');
  const toolsSection = html.slice(toolsSectionStart, evidenceSectionStart);
  assert.ok(!toolsSection.includes("evidence.export"), "evidence.export must not appear in the read/run tools card-grid");
  assert.ok(evidenceSectionStart > toolsSectionStart, "evidence.export section must be distinct from and after the read/run tools section");
  assert.ok(html.includes("no <code>tools/call</code> can reach it on its own"), "must state the ticket requirement");
});

test("agentsContentHtml: states the endpoint, protocol version, and each tool's can/cannot", () => {
  const html = agentsContentHtml({ port: 5555 });
  assert.ok(html.includes("http://127.0.0.1:5555/mcp"), "must state the port-specific endpoint");
  assert.ok(html.includes("2026-07-28"), "must state the current protocol version");
  assert.ok(html.includes("2025-06-18"), "must state the legacy fallback version");
  for (const name of ["catalog.search", "workflow.describe", "workflow.manifest_get", "workflow.dry_run", "workflow.run", "artifact.get", "artifact.verify", "evidence.export"]) {
    assert.ok(html.includes(name), `${name} must be listed`);
  }
});

test("agentsContentHtml: digest-level export is not implied to be a full signed bundle", () => {
  const html = agentsContentHtml({ port: 4173 });
  assert.ok(!/full signed evidence bundle\./i.test(html) || html.includes("not yet a full signed evidence bundle"), "must disclaim the full-bundle case");
});
