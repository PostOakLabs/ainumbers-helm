// Connect view: review connector contracts BEFORE consent — scope,
// destination, data-route, token location, expiry. No activation flow here;
// the connector runtime is a later hub WU (H-class).
import { fetchWithFallback } from "../api.mjs";

function methodBadgeList(methods) {
  return methods.map((m) => `<span class="field-row-badge">${m}</span>`).join(" ");
}

function tokenLocationOf(contract) {
  if (contract.vault_scope?.length) return contract.vault_scope.join(", ");
  return "no vault-backed secret (public client or deep-link)";
}

function connectorCard(entry) {
  const c = entry.contract;
  const expiry = entry.expiry ?? "no fixed expiry (revoke manually)";
  return `
    <article class="card" aria-labelledby="connector-${c.connector_id}">
      <h3 id="connector-${c.connector_id}">${c.name ?? c.connector_id}</h3>
      <p class="field-row"><span>${c.publisher}</span> · <span>v${c.connector_version}</span></p>
      <dl>
        <div class="field-row"><dt>Destination</dt><dd>${c.allowed_hosts.join(", ")}</dd></div>
        <div class="field-row"><dt>Data route</dt><dd>${methodBadgeList(c.allowed_methods)}</dd></div>
        <div class="field-row"><dt>Scopes</dt><dd>${(c.scopes ?? []).join(", ") || "none declared"}</dd></div>
        <div class="field-row"><dt>Token location</dt><dd>${tokenLocationOf(c)}</dd></div>
        <div class="field-row"><dt>Expiry</dt><dd>${expiry}</dd></div>
        <div class="field-row"><dt>Status</dt><dd>${entry.status ?? "not connected"}</dd></div>
      </dl>
      <details class="disclosure">
        <summary>Full contract</summary>
        <pre>${JSON.stringify(c, null, 2)}</pre>
      </details>
    </article>`;
}

export async function renderConnect(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Loading connector catalog…</p>`;
  const result = await fetchWithFallback("/connectors", { port, token });

  if (result.state === "unavailable") {
    root.innerHTML = `<p class="unavailable-state">Connector catalog isn't available in this daemon yet — the connector runtime ships in a later Helm wave. This page will populate automatically once it does.</p>`;
    return;
  }
  if (result.state === "missing") {
    root.innerHTML = `<p class="empty-state">Can't reach helmd on port ${port}. Start the daemon and open its pairing link to review connectors.</p>`;
    return;
  }

  const entries = result.data?.connectors ?? [];
  const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";

  if (entries.length === 0) {
    root.innerHTML = `<p class="empty-state">No connectors configured yet.${staleBadge}</p>`;
    return;
  }

  root.innerHTML = `
    <h2>Connect${staleBadge}</h2>
    <p class="field-row">Review scope, destination, and token location before any connector is authorized.</p>
    <div class="card-grid">${entries.map(connectorCard).join("")}</div>`;
}
