import { readTokenFromLocation, loadToken, saveToken, clearToken, loadPort, savePort, call } from "./api.mjs";
import { renderChoose } from "./views/choose.mjs";
import { renderCanvas } from "./views/canvas.mjs";
import { renderConnect } from "./views/connect.mjs";
import { renderRun } from "./views/run.mjs";
import { renderOperate } from "./views/operate.mjs";

const VIEWS = { choose: renderChoose, canvas: renderCanvas, connect: renderConnect, run: renderRun, operate: renderOperate };
const DEFAULT_VIEW = "choose";

function currentRoute() {
  const [view, query] = location.hash.replace(/^#\/?/, "").split("?");
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

function mountTokenForm(root, onPaired) {
  root.innerHTML = `
    <form class="token-form" aria-label="Pair with helmd">
      <label for="token-input">Pairing token</label>
      <input id="token-input" name="token" type="password" autocomplete="off" placeholder="paste token or open the CLI pairing link" />
      <label for="port-input">Port</label>
      <input id="port-input" name="port" type="number" min="1" max="65535" value="${loadPort()}" style="width:6rem" />
      <button type="submit">Pair</button>
    </form>
    <p class="empty-state">No token yet. Run <code>helmd start</code> and paste the token it prints, or open its printed <code>#token=</code> link directly.</p>`;
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
    mountTokenForm(app.main, () => render(app));
    setStatus(app.statusDot, app.statusLabel, "dormant", "not paired");
    return;
  }

  await VIEWS[view](app.main, { port, token, params });
  refreshConnectivity(port, token, app.statusDot, app.statusLabel);
}

export function boot() {
  const preHashToken = readTokenFromLocation();
  if (preHashToken) saveToken(preHashToken);

  const app = {
    main: document.getElementById("shell-main"),
    navLinks: Array.from(document.querySelectorAll("nav.shell-nav a")),
    statusDot: document.getElementById("status-dot"),
    statusLabel: document.getElementById("status-label"),
  };

  document.getElementById("unpair-btn")?.addEventListener("click", () => {
    clearToken();
    render(app);
  });

  window.addEventListener("hashchange", () => render(app));
  render(app);
  setInterval(() => {
    const token = loadToken();
    if (token) refreshConnectivity(loadPort(), token, app.statusDot, app.statusLabel);
  }, 10000);
}

boot();
