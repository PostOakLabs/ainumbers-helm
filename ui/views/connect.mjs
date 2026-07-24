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

// Daemon-side catalog is unavailable, missing, or empty in browser-mode-only
// use (no daemon at all) — browser connectors (below) are the only ones that
// apply then, so they render regardless of daemon state, per P3-D5's
// "one app, zero visible tiers" thesis (§0): a lock-with-reason on the
// daemon section, never a dead end for the whole view.
export async function renderConnect(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Loading connector catalog…</p>`;
  const result = await fetchWithFallback("/connectors", { port, token });

  let daemonHtml;
  if (result.state === "unavailable") {
    daemonHtml = `<p class="unavailable-state">Connector catalog isn't available in this daemon yet — the connector runtime ships in a later Helm wave. This page will populate automatically once it does.</p>`;
  } else if (result.state === "missing") {
    daemonHtml = `<p class="empty-state">Can't reach helmd on port ${port}. Start the daemon and open its pairing link to review daemon-side connectors.</p>`;
  } else {
    const entries = result.data?.connectors ?? [];
    const staleBadge = result.state === "stale" ? `<span class="stale-badge" role="status">stale — last seen ${result.at}</span>` : "";
    daemonHtml = entries.length === 0
      ? `<p class="empty-state">No daemon connectors configured yet.${staleBadge}</p>`
      : `<h2>Daemon connectors${staleBadge}</h2>
         <p class="field-row">Review scope, destination, and token location before any connector is authorized.</p>
         <div class="card-grid">${entries.map(connectorCard).join("")}</div>`;
  }

  root.innerHTML = `${daemonHtml}${browserConnectorsSection()}`;
  wireBrowserConnectors(root);
}
