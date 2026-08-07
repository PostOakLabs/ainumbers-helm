// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Agents / MCP view (HELM-UX-BUILD-SPEC.md §19.5.3). Content contract only —
// endpoint, protocol version, and each tool with what it can/cannot do. This
// view never itself performs the MCP handshake (it's a static description of
// hub/mcp.mjs, not a client) and never touches the bearer token beyond
// stating where it lives, per §19.3's three prohibitions:
//   - no copy-the-bearer-token-to-clipboard primary flow (explained, not a
//     button, below)
//   - no connector-authorization path of any kind (that stays on Connect)
//   - no presentation of this tab as a route to mcp.ainumbers.co (Helm's
//     non-integration with the hosted MCP server is deliberate, local-first)
// evidence.export is rendered in its own section, never inside the
// read/run card-grid, per §19.5.4/§19.4.
import { fetchWithFallback } from "../api.mjs";
import { blockedStateHtml, classifyBlockedState } from "../lib/blocked-state.mjs";
import { esc } from "../lib/esc.mjs";

const MCP_PATH = "/mcp";
// hub/mcp.mjs SUPPORTED_PROTOCOL_VERSIONS, HELM-MCP-FALLBACK-1 — restate
// here as copy, don't import the engine module into ui/ (out of fence, and
// this view would rather fail a stale-copy review than gain a hub/ import).
const PROTOCOL_VERSIONS = ["2026-07-28", "2025-06-18 (legacy)"];

// Mirrors hub/mcp.mjs's TOOLS list content in plain-English can/cannot form.
// Static copy, not daemon data — nothing here needs esc() for XSS, but
// toolCard() escapes anyway since a future edit could wire this to a live
// tools/list response and the guard should already be in place.
const READ_RUN_TOOLS = [
  { name: "catalog.search", can: "Search the compiled workflow and template catalog by name, outcome, or title.", cannot: "Cannot see anything outside the catalog — no filesystem or network access." },
  { name: "workflow.describe", can: "Return a workflow pack's name, outcome, and manifest digest.", cannot: "Cannot change the workflow or start anything." },
  { name: "workflow.manifest_get", can: "Return a workflow pack's raw DAG manifest — nodes, gates, actions.", cannot: "Cannot change the workflow or start anything." },
  { name: "workflow.dry_run", can: "Start a side-effect-free dry run. Returns a Task the client polls.", cannot: "Cannot write to any connected service — dry runs never call out." },
  { name: "workflow.run", can: "Start a real run. Returns a Task the client polls.", cannot: "Cannot supply run inputs the workflow itself didn't declare, and cannot authorize a new connector — only a workflow_id or template_slug is accepted." },
  { name: "artifact.get", can: "Fetch a run's digest-level artifact — state, execution_hash, per-step digests.", cannot: "Cannot fetch a run's underlying data, only its hashes and state." },
  { name: "artifact.verify", can: "Recompute a completed run's execution_hash from persisted state and compare it to the recorded value.", cannot: "Cannot verify a run that hasn't completed." },
];

const EVIDENCE_TOOL = {
  name: "evidence.export",
  can: "Export a run's digest-level evidence record (hash_verified) once a one-time consent ticket is presented.",
  cannot: "Cannot run from a tools/call alone — the ticket is minted by a route that isn't an MCP tool, and Phase-1 exports a digest-level record, not yet a full signed evidence bundle.",
};

function toolCard(t) {
  return `
    <article class="card" aria-labelledby="agents-tool-${esc(t.name)}">
      <h3 id="agents-tool-${esc(t.name)}"><code>${esc(t.name)}</code></h3>
      <p class="field-row"><strong>Can:</strong> ${esc(t.can)}</p>
      <p class="field-row"><strong>Cannot:</strong> ${esc(t.cannot)}</p>
    </article>`;
}

export function agentsContentHtml({ port }) {
  const endpoint = `http://127.0.0.1:${port}${MCP_PATH}`;
  return `
    <section aria-labelledby="agents-endpoint-heading">
      <h2 id="agents-endpoint-heading">Connect an agent or MCP client</h2>
      <p class="field-row">Point any MCP-compatible client at this endpoint. It only runs on this computer, on the loopback interface — nothing here reaches <code>mcp.ainumbers.co</code> or any other Post Oak Labs service.</p>
      <dl>
        <div class="field-row"><dt>Endpoint</dt><dd><code>${esc(endpoint)}</code></dd></div>
        <div class="field-row"><dt>Protocol version</dt><dd>${PROTOCOL_VERSIONS.map(esc).join(" or ")}</dd></div>
        <div class="field-row"><dt>Auth</dt><dd>Bearer token, sent as <code>Authorization: Bearer &lt;token&gt;</code> — the same token this browser tab is paired with.</dd></div>
      </dl>
      <p class="field-row-note">The token an MCP client needs is the same pairing token this tab already holds. To issue a fresh one for an agent — one that doesn't disturb any other paired tab — open a new pairing link from <a href="#/operate">Status</a>'s advanced pairing form. There's no copy-to-clipboard button on this page on purpose: paste the token once, into a client you trust, from wherever the pairing link took you.</p>
    </section>
    <section aria-labelledby="agents-tools-heading">
      <h2 id="agents-tools-heading">Read and run tools</h2>
      <div class="card-grid">${READ_RUN_TOOLS.map(toolCard).join("")}</div>
    </section>
    <section aria-labelledby="agents-evidence-heading">
      <h2 id="agents-evidence-heading">Evidence export — a separate tier</h2>
      <p class="field-row">This is not one of the read/run tools above, and no <code>tools/call</code> can reach it on its own. It needs a one-time consent ticket that only this UI mints, and each ticket works once.</p>
      <div class="card-grid">${toolCard(EVIDENCE_TOOL)}</div>
    </section>
    <section aria-labelledby="agents-scope-heading">
      <h2 id="agents-scope-heading">What this endpoint can't do</h2>
      <ul>
        <li>No connector authorization of any kind — connecting a service to a workflow always happens in this UI, never over MCP.</li>
        <li>No route to <code>mcp.ainumbers.co</code> or any hosted server — this endpoint only talks to the copy of Helm running on this computer.</li>
      </ul>
    </section>`;
}

export async function renderAgents(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Checking helmd…</p>`;
  const result = await fetchWithFallback("/health", { port, token });
  const blocked = classifyBlockedState(result);
  if (blocked) {
    // §13.5-style extra: the connection details below still apply even when
    // this tab can't currently confirm helmd is reachable — "the slot stays
    // reserved" is HELM-AGENTS-TAB-1's phrase for the endpoint being
    // unreachable, not for this tab going blank.
    root.innerHTML = blockedStateHtml(blocked, {
      port,
      status: result.status,
      route: result.route,
      body: "Helm is running, but this tab can't currently confirm the MCP endpoint is reachable. The connection details below are still correct once it is.",
      extra: agentsContentHtml({ port }),
    });
    return;
  }
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${esc(result.at)}</span>` : "";
  root.innerHTML = `<p class="field-row">helmd is running.${staleBadge}</p>${agentsContentHtml({ port })}`;
}
