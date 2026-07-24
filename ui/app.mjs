import { readTokenFromLocation, loadToken, saveToken, clearToken, loadFp, saveFp, clearFp, loadPort, savePort, call } from "./api.mjs";
import { BrowserJournalClient, offerJsonBundleDownload } from "./lib/browser-journal-client.mjs";
import { renderChoose } from "./views/choose.mjs";
import { renderCanvas } from "./views/canvas.mjs";
import { renderConnect } from "./views/connect.mjs";
import { renderRun } from "./views/run.mjs";
import { renderOperate } from "./views/operate.mjs";
import { renderVerify } from "./views/verify.mjs";
import { renderReview } from "./views/review.mjs";
import { renderHelp } from "./views/help.mjs";
import { renderRegister } from "./views/register.mjs";

const VIEWS = { choose: renderChoose, canvas: renderCanvas, connect: renderConnect, run: renderRun, verify: renderVerify, review: renderReview, operate: renderOperate, register: renderRegister, help: renderHelp };
const STATIC_VIEWS = new Set(["help"]);
const DEFAULT_VIEW = "choose";

// HELM-P3-G10: `#template=<slug>` is a shareable deep link (Teams/email),
// not the normal `#/view?query` shape — it always lands on Run with the
// template pre-loaded, one click from executing.
function currentRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  if (raw.startsWith("template=")) {
    return { view: "run", params: new URLSearchParams({ template: decodeURIComponent(raw.slice("template=".length)) }) };
  }
  const [view, query] = raw.split("?");
  return { view: VIEWS[view] ? view : DEFAULT_VIEW, params: new URLSearchParams(query || "") };
}

function setStatus(dot, label, state, text) {
  dot.dataset.state = state;
  label.textContent = text;
}

async function refreshConnectivity(port, token, dot, label) {
  const res = await call("/health", { port, token, timeoutMs: 2000 });
  if (res.ok) setStatus(dot, label, "live", "helmd connected");
  else if (res.status === 401 || res.status === 403) setStatus(dot, label, "down", "pairing required");
  else setStatus(dot, label, "down", "helmd unreachable (dormant)");
}

// Friendly welcome/empty state (Tim, 2026-07-23): first thing an unpaired
// visitor sees is "waiting for Helm," not a bare paste-a-token form. Manual
// pairing still works — it's tucked behind an <details> disclosure, since
// `helmd start` opens this page pre-paired for the normal first-run flow and
// this screen is mostly seen by people who closed that tab or lost the link.
function mountTokenForm(root, onPaired) {
  root.innerHTML = `
    <div class="welcome-state" aria-live="polite">
      <p class="welcome-title">Waiting for Helm on this computer&hellip;</p>
      <p class="empty-state">This tab isn't paired with helmd yet. To connect:</p>
      <ol class="steps">
        <li>Open a terminal (Command Prompt or PowerShell on Windows, Terminal on macOS or Linux).</li>
        <li>Type <code>helmd start</code> and press Enter. It opens a freshly paired tab automatically.</li>
        <li>Lost this tab or opened a bookmark? Run <code>helmd open</code> instead to get a fresh paired link.</li>
      </ol>
      <p class="empty-state">Don't have Helm installed yet? Get it at <a href="https://ainumbers.co/helm" rel="noopener">ainumbers.co/helm</a>.</p>
      <details class="disclosure">
        <summary>Advanced: pair by hand</summary>
        <form class="token-form" aria-label="Pair with helmd">
          <label for="token-input">Pairing token</label>
          <input id="token-input" name="token" type="password" autocomplete="off" placeholder="paste token or open the CLI pairing link" />
          <label for="port-input">Port</label>
          <input id="port-input" name="port" type="number" min="1" max="65535" value="${loadPort()}" style="width:6rem" />
          <button type="submit">Pair</button>
        </form>
      </details>
    </div>`;
  root.querySelector("form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const token = root.querySelector("#token-input").value.trim();
    const port = Number(root.querySelector("#port-input").value) || loadPort();
    savePort(port);
    if (token) {
      saveToken(token);
      onPaired();
    }
  });
}

async function render(app) {
  const port = loadPort();
  const token = loadToken();
  const { view, params } = currentRoute();

  app.navLinks.forEach((a) => {
    if (a.dataset.view === view) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });

  if (!token) {
    if (STATIC_VIEWS.has(view)) {
      await VIEWS[view](app.main, { port, token, params });
    } else {
      mountTokenForm(app.main, () => render(app));
    }
    setStatus(app.statusDot, app.statusLabel, "dormant", "not paired");
    return;
  }

  await VIEWS[view](app.main, { port, token, params });
  refreshConnectivity(port, token, app.statusDot, app.statusLabel);
}

const DENSITY_KEY = "helm.density";

// DEC-2 (locked): compact by default, comfortable is an opt-in toggle
// persisted per-browser.
function initDensityToggle(btn) {
  const apply = (density) => {
    document.documentElement.dataset.density = density;
    btn.setAttribute("aria-pressed", String(density === "comfortable"));
    btn.textContent = density === "comfortable" ? "Compact" : "Comfortable";
  };
  apply(localStorage.getItem(DENSITY_KEY) === "comfortable" ? "comfortable" : "compact");
  btn.addEventListener("click", () => {
    const next = document.documentElement.dataset.density === "comfortable" ? "compact" : "comfortable";
    localStorage.setItem(DENSITY_KEY, next);
    apply(next);
  });
}

// P3-D7: OPFS journal cache runs independently of daemon pairing — browser
// mode has no daemon at all. Best-effort: a browser without OPFS/Web Locks
// just never shows a banner and never records locally (daemon/export remain
// the source of truth in that case).
function startBrowserJournal() {
  const slot = document.getElementById("durability-banner-slot");
  const client = new BrowserJournalClient({
    onBannerChange: (html) => {
      if (slot) slot.innerHTML = html;
    },
    onOfferBundleDownload: (entries) => offerJsonBundleDownload(entries),
  });
  client.start().catch(() => {});
  return client;
}

export function boot() {
  const { token: preHashToken, pair, fp } = readTokenFromLocation();
  if (preHashToken) saveToken(preHashToken);
  // R15-F1 fix: pin the daemon identity fingerprint from this SAME trusted
  // link — only real helmd ever mints an `fp=` param (index.mjs cmdStart).
  if (fp) saveFp(fp);
  // P3-D9: best-effort, fire-and-forget — a failed redeem (link already
  // used, expired) never blocks this session, which already has the token.
  if (preHashToken && pair) {
    call("/pair/redeem", { port: loadPort(), token: preHashToken, method: "POST", body: { nonce: pair } }).catch(() => {});
  }

  initDensityToggle(document.getElementById("density-toggle"));

  const app = {
    main: document.getElementById("shell-main"),
    navLinks: Array.from(document.querySelectorAll("nav.shell-nav a")),
    statusDot: document.getElementById("status-dot"),
    statusLabel: document.getElementById("status-label"),
  };

  document.getElementById("unpair-btn")?.addEventListener("click", () => {
    clearToken();
    clearFp();
    render(app);
  });

  window.addEventListener("hashchange", () => render(app));
  render(app);
  window.helmJournal = startBrowserJournal(); // exposed for views to append to (P3-U2 landing point for run/operate views)
  setInterval(() => {
    const token = loadToken();
    if (token) refreshConnectivity(loadPort(), token, app.statusDot, app.statusLabel);
  }, 10000);
}

boot();
