// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
import { readTokenFromLocation, loadToken, saveToken, clearToken, loadFp, saveFp, clearFp, loadPort, savePort, call } from "./api.mjs";
import { initCompanyProfile } from "./lib/company-profile.mjs";
import { BrowserJournalClient, offerJsonBundleDownload } from "./lib/browser-journal-client.mjs";
import { skewBannerHtml, isDismissed, dismiss } from "./lib/version-skew.mjs";
import { TABS } from "./lib/tab-meta.mjs";
import { VIEWS } from "./lib/view-registry.mjs";
import { pairFormHtml, wirePairForm } from "./lib/pair-form.mjs";

// HELM-UX2-B-TABMETA (§12): TABS is the only place a tab's identity is
// written. VIEWS (lib/view-registry.mjs) maps an id to its render function —
// an id in TABS with no matching VIEWS entry fails the §12.5 gate rather
// than silently 404ing.
// HELM-P4-J5: Verify joins Home/Learn/Deadlines as pairing-free — a `#load=`
// link recipient (SharePoint/Teams share, no Helm install/pairing on that
// machine at all) must land straight on the bundle, not a "waiting for
// Helm" screen. Safe because verify.mjs is standalone by construction
// (never calls ../api.mjs). requiresPairing: false in tab-meta.mjs replaces
// the old STATIC_VIEWS set.
// §12.6: default route moves from choose to home.
const DEFAULT_VIEW = "home";

// HELM-P3-G10: `#template=<slug>` is a shareable deep link (Teams/email),
// not the normal `#/view?query` shape — it always lands on Run with the
// template pre-loaded, one click from executing.
//
// HELM-P4-J5: `#load=<https-url>` is the same idea for an evidence bundle —
// a SharePoint/Teams link-first share drops the app straight on Verify with
// the bundle pre-fetched, no file picker round-trip. Hash (not `?config=`'s
// query string) because link-sharing UIs commonly re-host or proxy a shared
// URL's query string but leave the fragment alone, and because `helmd open`
// already treats the hash as the deep-link channel (`#token=`, `#template=`).
function currentRoute() {
  const raw = location.hash.replace(/^#\/?/, "");
  if (raw.startsWith("template=")) {
    return { view: "run", params: new URLSearchParams({ template: decodeURIComponent(raw.slice("template=".length)) }) };
  }
  if (raw.startsWith("load=")) {
    return { view: "verify", params: new URLSearchParams({ load: decodeURIComponent(raw.slice("load=".length)) }) };
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

// HELM-UX-1 §7: one shell-owned EventSource, reused across every view
// (§7.3 — a second, view-level stream on Run would double-subscribe and
// ratchet MAX_SSE_CONNECTIONS toward its cap on a hash-router shell). Fed by
// a short-lived ticket per connect (§7.4), never the durable bearer token.
// #status-dot is the only activity indicator (§7.1) — this drives its pulse,
// it never creates a second one. Reconnect is manual (setTimeout), not the
// browser's built-in EventSource retry, because a ticket is single-use: an
// automatic retry would replay an already-consumed ticket and loop on 401.
const PULSE_MS = 700;
const RECENT_MS = 4000;
const RECONNECT_MS = 3000;

function createActivityStream(port, token, dot, label) {
  let es = null;
  let runId = null;
  let closed = false;
  let connected = null; // null = never connected yet, else last known live/dead
  let reconnectTimer = null;
  let pulseTimer = null;
  let recentTimer = null;
  const listeners = new Set();

  // §7.5: only the low-frequency, human-meaningful transition goes into the
  // live region (#status-label) — not per-heartbeat/per-event noise, which
  // is what the aria-hidden pulse above is for instead.
  function setConnected(live) {
    if (connected === live) return;
    connected = live;
    if (label) label.textContent = live ? "connection restored" : "connection lost — retrying";
  }

  // §7.5: aria-hidden decorative flash, one-shot per event (never a repeating
  // loop) with a reduced-motion-safe fallback — the animation is disabled
  // under prefers-reduced-motion in theme.css, but the static data-recent
  // ring it also sets still conveys "recently active" without motion.
  function pulse() {
    dot.dataset.pulse = "true";
    dot.dataset.recent = "true";
    clearTimeout(pulseTimer);
    clearTimeout(recentTimer);
    pulseTimer = setTimeout(() => dot.removeAttribute("data-pulse"), PULSE_MS);
    recentTimer = setTimeout(() => dot.removeAttribute("data-recent"), RECENT_MS);
  }

  function scheduleReconnect() {
    if (closed || reconnectTimer) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, RECONNECT_MS);
  }

  async function connect() {
    if (closed || typeof EventSource === "undefined") return;
    const res = await call("/events/ticket", { port, token, method: "POST", timeoutMs: 3000 });
    if (closed) return;
    if (!res.ok) return scheduleReconnect();
    const qs = new URLSearchParams({ ticket: res.data?.ticket ?? "" });
    if (runId) qs.set("run_id", runId);
    try {
      es = new EventSource(`http://127.0.0.1:${port}/events?${qs}`);
    } catch {
      return scheduleReconnect();
    }
    es.addEventListener("ready", () => {
      pulse();
      setConnected(true);
    });
    es.addEventListener("heartbeat", () => {
      pulse();
      setConnected(true);
    });
    es.addEventListener("progress", (ev) => {
      pulse();
      setConnected(true);
      let data = null;
      try {
        data = JSON.parse(ev.data);
      } catch {
        /* malformed event, still counts as activity */
      }
      listeners.forEach((fn) => fn(data));
    });
    es.onerror = () => {
      setConnected(false);
      es?.close();
      es = null;
      scheduleReconnect();
    };
  }

  connect();

  return {
    // Re-points the shared connection at a specific run's progress events —
    // called by the Run view, never opens a second connection.
    setRunId(id) {
      if (id === runId) return;
      runId = id;
      es?.close();
      es = null;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      connect();
    },
    subscribeProgress(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    close() {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      es?.close();
    },
  };
}

let activityStream = null;
let activityStreamKey = null;

function ensureActivityStream(port, token, dot, label) {
  if (!token) {
    activityStream?.close();
    activityStream = null;
    activityStreamKey = null;
    return null;
  }
  const key = `${port}:${token}`;
  if (activityStream && activityStreamKey === key) return activityStream;
  activityStream?.close();
  activityStreamKey = key;
  activityStream = createActivityStream(port, token, dot, label);
  return activityStream;
}

// Friendly welcome/empty state (Tim, 2026-07-23): first thing an unpaired
// visitor sees is "waiting for Helm," not a bare paste-a-token form. Manual
// pairing still works — it's tucked behind an <details> disclosure, since
// `helmd start` opens this page pre-paired for the normal first-run flow and
// this screen is mostly seen by people who closed that tab or lost the link.
//
// This recovery copy deliberately never names a terminal or a command to
// type — the fix is "open the Helm app" / reinstall. HELM-AUTOSTART-1: it no
// longer claims Helm starts by itself either. Autostart is opt-in and off by
// default now, so on most machines nothing is going to bring the daemon back
// on its own and telling the user "no action needed" would strand them on a
// page that never reconnects.
//
// HELM-PAIR-UX-1: the screen above USED TO just say "waiting" and never
// actually checked anything — no probe, no poll, so it stayed "waiting" even
// after Helm started, or stayed "waiting" forever if Helm was never running
// at all. Root cause (HELM-PAIR-DIAG-1): the pairing token lives in
// sessionStorage (P3-D9, tab-lifetime only), so this screen is normal and
// expected the moment a paired tab is closed — the fix is telling the user
// WHICH of the two different situations they're in, not guessing. This now
// probes GET /health (no token — a plain reachability check, never the
// pairing check itself) to tell "Helm isn't running at all" apart from
// "Helm is running, this tab just isn't the paired one," and re-probes every
// few seconds so the page catches up on its own instead of sitting on stale
// copy. Plain language only in the two headline states — "token",
// "loopback", "origin" stay out of them; the pair-by-hand form below keeps
// the technical field names it always had, since that's the disclosed
// Advanced section.
const CONNECT_PROBE_MS = 3000;
let connectProbeTimer = null;

async function probeHelmdReachable(port) {
  const res = await call("/health", { port, token: null, timeoutMs: 2000 });
  // status 0 = the fetch itself failed (refused/timed out) — nothing is
  // listening. Any other status, including a 401 this unauthenticated probe
  // is expected to get, means something answered on that port.
  return res.status !== 0;
}

function connectDiagnosisHtml(state) {
  if (state === "checking") {
    return `<p class="welcome-title">Checking for Helm&hellip;</p>
      <p class="empty-state">Looking for Helm on this computer.</p>`;
  }
  if (state === "unreachable") {
    return `<p class="welcome-title">Helm isn't running</p>
      <p class="empty-state">This computer isn't running Helm right now. This page keeps checking on its own — no need to reload it.</p>
      <p class="empty-state">Open the Helm app (check your login items or Start menu), or reinstall from <a href="https://ainumbers.co/helm" rel="noopener">ainumbers.co/helm</a> if it isn't there.</p>`;
  }
  return `<p class="welcome-title">Helm is running, but this browser tab isn't connected to it</p>
    <p class="empty-state">A Helm connection only works in the browser tab it started in. If you connected Helm before, switch back to that tab.</p>
    <p class="empty-state">Otherwise, open the Helm app again (login items or Start menu) — it opens a fresh, already-connected tab.</p>`;
}

function mountTokenForm(root, onPaired, port) {
  root.innerHTML = `
    <div class="welcome-state" aria-live="polite">
      <div id="connect-diagnosis">${connectDiagnosisHtml("checking")}</div>
      <p class="empty-state">New to Helm? See the <a href="#/learn">step-by-step connection guide</a>.</p>
      <details class="disclosure">
        <summary>Advanced: pair by hand</summary>
        ${pairFormHtml()}
      </details>
    </div>`;
  wirePairForm(root, onPaired);

  const tick = async () => {
    const reachable = await probeHelmdReachable(port);
    const slot = root.querySelector("#connect-diagnosis");
    if (slot) slot.innerHTML = connectDiagnosisHtml(reachable ? "not-paired" : "unreachable");
  };
  tick();
  connectProbeTimer = setInterval(tick, CONNECT_PROBE_MS);
}

// §12.3: the shell owns the page title. Views delete their own <h2> and
// render into #view-content only; #view-header is never touched by a view.
function renderViewHeader(app, view) {
  const tab = TABS.find((t) => t.id === view);
  app.viewHeader.innerHTML = tab ? `<h1>${tab.label}</h1><p class="tab-intro">${tab.intro}</p>` : "";
}

async function render(app) {
  if (connectProbeTimer) {
    clearInterval(connectProbeTimer);
    connectProbeTimer = null;
  }
  const port = loadPort();
  const token = loadToken();
  const { view, params } = currentRoute();

  app.navLinks.forEach((a) => {
    if (a.dataset.view === view) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  renderViewHeader(app, view);

  const requiresPairing = TABS.find((t) => t.id === view)?.requiresPairing ?? true;

  if (!token) {
    ensureActivityStream(port, null, app.statusDot, app.statusLabel);
    if (!requiresPairing) {
      await VIEWS[view](app.viewContent, { port, token, params, activityStream: null });
    } else {
      mountTokenForm(app.viewContent, () => render(app), port);
    }
    setStatus(app.statusDot, app.statusLabel, "dormant", "not paired");
    return;
  }

  const activityStream = ensureActivityStream(port, token, app.statusDot, app.statusLabel);
  await VIEWS[view](app.viewContent, { port, token, params, activityStream });
  refreshConnectivity(port, token, app.statusDot, app.statusLabel);
}

// HELM-P4-J4: skew banner — polls the daemon's own /version-check (which
// does the real comparison server-side, since the page's CSP is
// `connect-src 'self'` and can't reach ainumbers.co directly). Best-effort:
// a token-less or unreachable daemon just renders nothing, same as the
// connectivity dot.
async function refreshVersionSkew(port, token, slot) {
  if (!token || !slot) return;
  const res = await call("/version-check", { port, token, timeoutMs: 5000 });
  if (!res.ok) return;
  const vc = res.data;
  if (vc?.checked && !vc.upToDate && isDismissed(vc.latestVersion)) return;
  slot.innerHTML = skewBannerHtml(vc);
  slot.querySelector("#version-skew-dismiss")?.addEventListener("click", () => {
    dismiss(vc.latestVersion);
    slot.innerHTML = "";
  });
}

// P3-D7: OPFS journal cache runs independently of daemon pairing — browser
// mode has no daemon at all. Best-effort: a browser without OPFS/Web Locks
// just never shows a banner and never records locally (daemon/export remain
// the source of truth in that case).
function startBrowserJournal() {
  const slot = document.getElementById("durability-banner-slot");
  const client = new BrowserJournalClient({
    // §14.2: the banner tells the user to export while the control lives
    // elsewhere — wire its button to the same download hook used after
    // every run, so a stranded reader isn't told about a control they
    // can't find.
    onBannerChange: (html) => {
      if (!slot) return;
      slot.innerHTML = html;
      slot.querySelector("#durability-banner-download")?.addEventListener("click", () => offerJsonBundleDownload(client.entries));
    },
    onOfferBundleDownload: (entries) => offerJsonBundleDownload(entries),
  });
  client.start().catch(() => {});
  return client;
}

// §12.3/§12.4: nav is generated from TABS, grouped per §12.6 — the wrapper
// keeps the HELM-UX-1 §6.2/§6.3 role="group" + aria-label + data-group
// contract theme.css's sibling-selector separator relies on, so reordering
// or adding a tab here can never silently break the separator or grouping.
function generateNav(navEl) {
  navEl.innerHTML = "";
  let currentGroup = null;
  let groupEl = null;
  for (const tab of TABS) {
    if (tab.group !== currentGroup) {
      currentGroup = tab.group;
      groupEl = document.createElement("div");
      groupEl.setAttribute("role", "group");
      groupEl.setAttribute("aria-label", currentGroup);
      groupEl.dataset.group = currentGroup.toLowerCase();
      navEl.appendChild(groupEl);
    }
    if (tab.disabled) {
      // HELM-UX2-J-AGENTS-SLOT (§19.2): reserved slot, no route reachable —
      // a <span> has no href to activate, so there's nothing to click through
      // to an empty/placeholder view. aria-disabled tells AT it's inert.
      const span = document.createElement("span");
      span.className = "shell-nav-disabled";
      span.setAttribute("aria-disabled", "true");
      span.textContent = tab.label;
      groupEl.appendChild(span);
      continue;
    }

    const a = document.createElement("a");
    a.href = `#/${tab.id}`;
    a.dataset.view = tab.id;
    a.textContent = tab.label;
    groupEl.appendChild(a);
  }
  return Array.from(navEl.querySelectorAll("a"));
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

  const app = {
    viewHeader: document.getElementById("view-header"),
    viewContent: document.getElementById("view-content"),
    navLinks: generateNav(document.querySelector("nav.shell-nav")),
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
  // HELM-P4-J1: fire-and-forget, same pattern as pair/redeem above — a slow
  // or unreachable config host must never delay first paint. If a profile
  // does load, re-render once so branding/curation apply without a reload.
  initCompanyProfile().then((profile) => {
    if (profile) render(app);
  });
  window.helmJournal = startBrowserJournal(); // exposed for views to append to (P3-U2 landing point for run/operate views)
  setInterval(() => {
    const token = loadToken();
    if (token) refreshConnectivity(loadPort(), token, app.statusDot, app.statusLabel);
  }, 10000);

  // HELM-P4-J4: once at boot, then hourly — the daemon proxies the actual
  // check (D10 passive-notice cadence), so this is cheap to leave running.
  const versionSkewSlot = document.getElementById("version-skew-banner-slot");
  const checkSkew = () => {
    const token = loadToken();
    if (token) refreshVersionSkew(loadPort(), token, versionSkewSlot).catch(() => {});
  };
  checkSkew();
  setInterval(checkSkew, 60 * 60 * 1000);
}

boot();
