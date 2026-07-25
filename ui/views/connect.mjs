// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Connect view: review connector contracts BEFORE consent — scope,
// destination, data-route, token location, expiry — for daemon-side
// connectors (unchanged from H6/P2).
//
// HELM-P3-U4 adds a second, daemon-free section below it: browser-mode
// OAuth (Microsoft SPA, Google drive.file+Picker) and the GitHub PAT
// paste-in, per HELM-PHASE3-BUILD-SPEC.md P3-D5. Tokens are vaulted through
// ui/lib/vault-token-store.mjs (never plaintext storage) using a passphrase-
// enrolled vault record kept in localStorage (`helm.browser.vault.record` —
// the WRAPPED DEK only, never the DEK itself, same shape vault.mjs already
// produces). A dedicated WebAuthn-PRF enrollment screen (the primary vault
// UX per P3-D8) is a follow-on; this view's passphrase prompt is the
// minimal working path so browser OAuth has a real, vaulted destination for
// its tokens today rather than nowhere to put them.
import { fetchWithFallback } from "../api.mjs";
import {
  MICROSOFT_SPA,
  GOOGLE_DRIVE_FILE,
  startBrowserFlow,
  completeBrowserFlow,
  looksLikeFineGrainedPat,
  verifyGithubPat,
} from "../lib/oauth-browser.mjs";
import { consumeRelayedResult } from "../oauth-callback.mjs";
import { unlockRecord, enrollPassphrase, VaultWeakPassphraseError, PASSPHRASE_MIN_LENGTH } from "../lib/vault.mjs";
import { VaultTokenStore, openIndexedDbTokenStore } from "../lib/vault-token-store.mjs";
import { esc } from "../lib/esc.mjs";
import { blockedStateHtml, classifyBlockedState } from "../lib/blocked-state.mjs";
import {
  loadCustomConnectors,
  validateCandidate,
  addCustomConnector,
  removeCustomConnector,
  hostDisplayParts,
} from "../lib/custom-connectors.mjs";

const VAULT_RECORD_KEY = "helm.browser.vault.record";
const OAUTH_CLIENT_ID_KEYS = { microsoft: "helm.oauth.clientId.microsoft", google: "helm.oauth.clientId.google" };
const TOKEN_REFS = { microsoft: "vault://helm/browser-oauth/microsoft", google: "vault://helm/browser-oauth/google", github: "vault://helm/browser-oauth/github" };

function loadVaultRecord() {
  const raw = localStorage.getItem(VAULT_RECORD_KEY);
  return raw ? JSON.parse(raw) : null;
}
function saveVaultRecord(record) {
  localStorage.setItem(VAULT_RECORD_KEY, JSON.stringify(record));
}

// Gets a usable DEK for this browser: unlocks the existing passphrase-vault
// record, or enrolls a brand-new one on first use. `window.prompt` is a
// deliberately minimal stand-in for the dedicated enroll/unlock screen the
// vault (P3-D8) eventually ships — swap this one function out when that
// screen lands; nothing else in this view needs to change.
async function ensureVaultDek() {
  const existing = loadVaultRecord();
  if (existing) {
    const passphrase = window.prompt("Enter your Helm vault passphrase to store this connection:");
    if (!passphrase) throw new Error("vault unlock cancelled");
    return unlockRecord(existing, { passphrase });
  }
  let prompt = `Set a passphrase to protect connector tokens stored in this browser (min ${PASSPHRASE_MIN_LENGTH} characters, several distinct):`;
  for (;;) {
    const passphrase = window.prompt(prompt);
    if (!passphrase) throw new Error("vault enrollment cancelled");
    try {
      const { dek, record } = await enrollPassphrase(passphrase);
      saveVaultRecord(record);
      return dek;
    } catch (err) {
      if (!(err instanceof VaultWeakPassphraseError)) throw err;
      prompt = `${err.message}. Try again:`;
    }
  }
}

async function tokenStoreFor() {
  const dek = await ensureVaultDek();
  const idbStore = await openIndexedDbTokenStore();
  return new VaultTokenStore(dek, idbStore);
}

function redirectUriFor() {
  return new URL("../oauth-callback.html", location.href).toString();
}

async function beginMicrosoftConnect(root) {
  const clientId = localStorage.getItem(OAUTH_CLIENT_ID_KEYS.microsoft) || window.prompt("Microsoft SPA app client ID:");
  if (!clientId) return;
  localStorage.setItem(OAUTH_CLIENT_ID_KEYS.microsoft, clientId);
  const { authorizationUrl } = await startBrowserFlow({
    provider: "microsoft",
    authorizationEndpoint: MICROSOFT_SPA.authorizationEndpoint(),
    clientId,
    redirectUri: redirectUriFor(),
    scopes: MICROSOFT_SPA.defaultScopes,
  });
  location.href = authorizationUrl; // top-level navigation only (P3-D3) — never window.open
}

async function beginGoogleConnect(root) {
  const clientId = localStorage.getItem(OAUTH_CLIENT_ID_KEYS.google) || window.prompt("Google OAuth client ID:");
  if (!clientId) return;
  localStorage.setItem(OAUTH_CLIENT_ID_KEYS.google, clientId);
  const { authorizationUrl } = await startBrowserFlow({
    provider: "google",
    authorizationEndpoint: GOOGLE_DRIVE_FILE.authorizationEndpoint,
    clientId,
    redirectUri: redirectUriFor(),
    scopes: GOOGLE_DRIVE_FILE.defaultScopes,
  });
  location.href = authorizationUrl;
}

async function completePendingBrowserOAuth(statusEl) {
  const relayed = consumeRelayedResult();
  if (!relayed) return;
  if (!relayed.ok) {
    statusEl.textContent = `Connection failed: ${relayed.error}`;
    return;
  }
  // Either provider could have redirected here — completeBrowserFlow itself
  // knows which one via its own sessionStorage flow record, keyed by
  // provider, so try each; only the one with a matching pending flow (and
  // matching state) succeeds.
  for (const [provider, preset, tokenRef] of [
    ["microsoft", MICROSOFT_SPA, TOKEN_REFS.microsoft],
    ["google", GOOGLE_DRIVE_FILE, TOKEN_REFS.google],
  ]) {
    try {
      const tokens = await completeBrowserFlow({ provider, code: relayed.code, state: relayed.state, tokenEndpoint: preset.tokenEndpoint });
      const tokenStore = await tokenStoreFor();
      await tokenStore.setToken(tokenRef, tokens);
      statusEl.textContent = provider === "microsoft"
        ? `Microsoft connected. ${MICROSOFT_SPA.reconnectCopy}`
        : "Google connected (drive.file scope — pick files via the Picker to grant access to them).";
      return;
    } catch {
      // not this provider's flow — try the next
    }
  }
}

async function submitGithubPat(input, statusEl) {
  const pat = input.value.trim();
  if (!looksLikeFineGrainedPat(pat)) {
    statusEl.textContent = "That doesn't look like a fine-grained PAT (expected github_pat_...).";
    return;
  }
  statusEl.textContent = "Verifying token…";
  const result = await verifyGithubPat(pat);
  if (!result.ok) {
    statusEl.textContent = `GitHub rejected that token (status ${result.status}).`;
    return;
  }
  const tokenStore = await tokenStoreFor();
  await tokenStore.setToken(TOKEN_REFS.github, { access_token: pat });
  input.value = "";
  statusEl.textContent = `GitHub connected as ${result.login}.`;
}

function browserConnectorsSection() {
  return `
    <section aria-labelledby="browser-connectors-heading">
      <h2 id="browser-connectors-heading">Browser-mode connectors</h2>
      <p class="field-row">These run entirely in this browser (no daemon needed). Tokens are encrypted and stored on this device only.</p>
      <p id="browser-oauth-status" role="status" aria-live="polite"></p>
      <div class="card-grid">
        <article class="card">
          <h3>Microsoft</h3>
          <p class="field-row">${MICROSOFT_SPA.reconnectCopy}</p>
          <button type="button" id="connect-microsoft">Connect Microsoft</button>
        </article>
        <article class="card">
          <h3>Google Drive</h3>
          <p class="field-row">drive.file scope only — grants access to files you pick, never full Drive read access.</p>
          <button type="button" id="connect-google">Connect Google</button>
        </article>
        <article class="card">
          <h3>GitHub</h3>
          <p class="field-row">Paste a fine-grained personal access token (github_pat_...).</p>
          <input type="password" id="github-pat-input" placeholder="github_pat_..." autocomplete="off" />
          <button type="button" id="connect-github">Add token</button>
        </article>
      </div>
    </section>`;
}

function wireBrowserConnectors(root) {
  const statusEl = root.querySelector("#browser-oauth-status");
  root.querySelector("#connect-microsoft")?.addEventListener("click", () => beginMicrosoftConnect(root).catch((e) => (statusEl.textContent = String(e.message ?? e))));
  root.querySelector("#connect-google")?.addEventListener("click", () => beginGoogleConnect(root).catch((e) => (statusEl.textContent = String(e.message ?? e))));
  root.querySelector("#connect-github")?.addEventListener("click", () => {
    submitGithubPat(root.querySelector("#github-pat-input"), statusEl).catch((e) => (statusEl.textContent = String(e.message ?? e)));
  });
  completePendingBrowserOAuth(statusEl).catch((e) => (statusEl.textContent = String(e.message ?? e)));
}

function methodBadgeList(methods) {
  return methods.map((m) => `<span class="field-row-badge">${esc(m)}</span>`).join(" ");
}

function tokenLocationOf(contract) {
  if (contract.vault_scope?.length) return contract.vault_scope.join(", ");
  return "no vault-backed secret (public client or deep-link)";
}

// Everything under `entry`/`entry.contract` is daemon-supplied and untrusted
// (HELM-UX-BUILD-SPEC.md §16.2) — the full-contract <pre> in particular must
// go through esc() because JSON.stringify does not escape "<", making it the
// reliable breakout vector once a real connector runtime lands (HELM-UX2-G-IMPORT).
export function connectorCard(entry) {
  const c = entry.contract;
  const expiry = entry.expiry ?? "no fixed expiry (revoke manually)";
  return `
    <article class="card" aria-labelledby="connector-${esc(c.connector_id)}">
      <h3 id="connector-${esc(c.connector_id)}">${esc(c.name ?? c.connector_id)}</h3>
      <p class="field-row"><span>${esc(c.publisher)}</span> · <span>v${esc(c.connector_version)}</span></p>
      <dl>
        <div class="field-row"><dt>Destination</dt><dd>${esc(c.allowed_hosts.join(", "))}</dd></div>
        <div class="field-row"><dt>Data route</dt><dd>${methodBadgeList(c.allowed_methods)}</dd></div>
        <div class="field-row"><dt>Scopes</dt><dd>${esc((c.scopes ?? []).join(", ")) || "none declared"}</dd></div>
        <div class="field-row"><dt>Token location</dt><dd>${esc(tokenLocationOf(c))}</dd></div>
        <div class="field-row"><dt>Expiry</dt><dd>${esc(expiry)}</dd></div>
        <div class="field-row"><dt>Status</dt><dd>${esc(entry.status ?? "not connected")}</dd></div>
      </dl>
      <details class="disclosure">
        <summary>Full contract</summary>
        <pre>${esc(JSON.stringify(c, null, 2))}</pre>
      </details>
    </article>`;
}

// §16.6: hosts render monospace (<code> is monospace by default — no new
// CSS needed) with the registrable domain emphasised via <strong> and never
// truncated, plus a Punycode subline for any non-ASCII (IDN homograph) host.
function hostsHtml(hosts) {
  return hosts
    .map((h) => {
      const { host, registrable, punycode } = hostDisplayParts(h);
      const prefix = esc(host.slice(0, host.length - registrable.length));
      const puny = punycode ? ` <span class="field-row-badge">Punycode: ${esc(punycode)}</span>` : "";
      return `<div><code>${prefix}<strong>${esc(registrable)}</strong></code>${puny}</div>`;
    })
    .join("");
}

// §16.7: badged, never rendered in the daemon-connectors section, digest
// stored so a later silent edit under the same id is detectable.
function customConnectorCard(entry) {
  const c = entry.contract;
  return `
    <article class="card" aria-labelledby="custom-connector-${esc(c.connector_id)}">
      <span class="stale-badge" role="status">Added by you. Not checked by Post Oak Labs.</span>
      <h3 id="custom-connector-${esc(c.connector_id)}">${esc(c.name ?? c.connector_id)}</h3>
      <p class="field-row"><span>${esc(c.publisher)}</span> · <span>v${esc(c.connector_version)}</span></p>
      <dl>
        <div class="field-row"><dt>Destination</dt><dd>${hostsHtml(c.allowed_hosts)}</dd></div>
        <div class="field-row"><dt>Data route</dt><dd>${methodBadgeList(c.allowed_methods)}</dd></div>
        <div class="field-row"><dt>Scopes</dt><dd>${esc((c.scopes ?? []).join(", ")) || "none declared"}</dd></div>
        <div class="field-row"><dt>Contract digest</dt><dd><code>${esc(entry.contractDigest)}</code></dd></div>
        <div class="field-row"><dt>Added</dt><dd>${esc(entry.addedAt)}</dd></div>
      </dl>
      <details class="disclosure">
        <summary>Full contract</summary>
        <pre>${esc(JSON.stringify(c, null, 2))}</pre>
      </details>
      <button type="button" data-remove-id="${esc(c.connector_id)}">Remove</button>
    </article>`;
}

// §16.4 step 2: preview only — rendered from a VALIDATED contract but not
// yet added. No remove button (nothing to remove yet); the confirm copy
// states plainly that adding is an allowlist entry, not a credential grant.
function customConnectorPreviewCard(contract) {
  return `
    <article class="card" aria-labelledby="custom-connector-preview-heading">
      <span class="stale-badge" role="status">Preview — not added yet</span>
      <h3 id="custom-connector-preview-heading">${esc(contract.name ?? contract.connector_id)}</h3>
      <p class="field-row"><span>${esc(contract.publisher)}</span> · <span>v${esc(contract.connector_version)}</span></p>
      <dl>
        <div class="field-row"><dt>Destination</dt><dd>${hostsHtml(contract.allowed_hosts)}</dd></div>
        <div class="field-row"><dt>Data route</dt><dd>${methodBadgeList(contract.allowed_methods)}</dd></div>
        <div class="field-row"><dt>Scopes</dt><dd>${esc((contract.scopes ?? []).join(", ")) || "none declared"}</dd></div>
      </dl>
      <details class="disclosure">
        <summary>Full contract</summary>
        <pre>${esc(JSON.stringify(contract, null, 2))}</pre>
      </details>
      <p class="field-row">Adding this creates an allowlist entry only — it grants no credential until you vault one, and it is never checked by Post Oak Labs.</p>
    </article>`;
}

// §16.8: last section on Connect, collapsed by default — Connect's job is
// reviewing before consent, an authoring affordance at the top inverts it.
function customConnectorsSection() {
  return `
    <details class="disclosure" id="custom-connector-import">
      <summary>Add a custom connector</summary>
      <p class="field-row">Only add a contract you trust — it widens the egress allowlist for whatever's inside it. Validated with the same schema and digest logic the connector runtime itself uses.</p>
      <div class="field-row">
        <label for="custom-connector-file">Load from a file</label>
        <input type="file" id="custom-connector-file" accept="application/json,.json" />
      </div>
      <div class="field-row">
        <label for="custom-connector-text">Or paste the contract JSON</label>
        <textarea id="custom-connector-text" rows="8"></textarea>
      </div>
      <button type="button" id="custom-connector-validate">Validate</button>
      <p id="custom-connector-message" role="status" aria-live="polite"></p>
      <div id="custom-connector-preview"></div>
      <h3>Connectors added by you</h3>
      <div class="card-grid" id="custom-connector-list"></div>
    </details>`;
}

function wireCustomConnectorImport(root, { knownIds }) {
  const fileInput = root.querySelector("#custom-connector-file");
  const textArea = root.querySelector("#custom-connector-text");
  const messageEl = root.querySelector("#custom-connector-message");
  const previewEl = root.querySelector("#custom-connector-preview");
  const listEl = root.querySelector("#custom-connector-list");

  fileInput?.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { textArea.value = String(reader.result ?? ""); };
    reader.readAsText(file);
  });

  function renderList() {
    const entries = loadCustomConnectors();
    listEl.innerHTML = entries.length
      ? entries.map(customConnectorCard).join("")
      : `<p class="empty-state">No custom connectors added yet.</p>`;
    listEl.querySelectorAll("[data-remove-id]").forEach((btn) => {
      btn.addEventListener("click", () => {
        removeCustomConnector(btn.dataset.removeId);
        renderList();
      });
    });
  }
  renderList();

  root.querySelector("#custom-connector-validate")?.addEventListener("click", async () => {
    previewEl.innerHTML = "";
    const text = textArea.value.trim();
    if (!text) {
      messageEl.textContent = "Nothing to validate — load a file or paste contract JSON first.";
      return;
    }
    const result = await validateCandidate(text, { knownIds });
    if (!result.ok) {
      messageEl.textContent = result.message;
      return;
    }
    messageEl.textContent = "Valid contract — review before adding.";
    previewEl.innerHTML = `${customConnectorPreviewCard(result.contract)}
      <button type="button" id="custom-connector-confirm">Add connector</button>
      <button type="button" id="custom-connector-cancel">Cancel</button>`;
    previewEl.querySelector("#custom-connector-confirm").addEventListener("click", () => {
      try {
        addCustomConnector(result);
        messageEl.textContent = `Added "${result.contract.connector_id}". It's an allowlist entry only — no credential is granted until one is vaulted.`;
        previewEl.innerHTML = "";
        textArea.value = "";
        renderList();
      } catch (err) {
        messageEl.textContent = err.message;
      }
    });
    previewEl.querySelector("#custom-connector-cancel").addEventListener("click", () => {
      previewEl.innerHTML = "";
      messageEl.textContent = "";
    });
  });
}

// Daemon-side catalog is unavailable, missing, or empty in browser-mode-only
// use (no daemon at all) — browser connectors (below) are the only ones that
// apply then, so they render regardless of daemon state, per P3-D5's
// "one app, zero visible tiers" thesis (§0): a lock-with-reason on the
// daemon section, never a dead end for the whole view.
export async function renderConnect(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Loading connector catalog…</p>`;
  const result = await fetchWithFallback("/connectors", { port, token });

  let daemonHtml;
  let daemonIds = [];
  const blocked = classifyBlockedState(result);
  if (blocked) {
    daemonHtml = blockedStateHtml(blocked, {
      port,
      status: result.status,
      route: result.route,
      body: blocked === "too-old"
        ? "helmd answered, but the connector catalog isn't served by this version of Helm yet."
        : "Helm is running, but this tab can't reach the daemon-side connector catalog right now.",
    });
  } else {
    const entries = result.data?.connectors ?? [];
    daemonIds = entries.map((e) => e.contract?.connector_id).filter(Boolean);
    const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";
    daemonHtml = entries.length === 0
      ? `<p class="empty-state">No daemon connectors configured yet.${staleBadge}</p>`
      : `<h2>Daemon connectors${staleBadge}</h2>
         <p class="field-row">Review scope, destination, and token location before any connector is authorized.</p>
         <div class="card-grid">${entries.map(connectorCard).join("")}</div>`;
  }

  root.innerHTML = `${daemonHtml}${browserConnectorsSection()}${customConnectorsSection()}`;
  wireBrowserConnectors(root);
  wireCustomConnectorImport(root, { knownIds: daemonIds });
}
