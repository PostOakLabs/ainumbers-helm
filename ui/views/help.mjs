// Help view (HELM-P2-U6, HELM-PHASE2-BUILD-SPEC.md §5): static explainer, no
// daemon dependency — renders even when the browser has no pairing token, so
// it's reachable from the "not paired" welcome state (app.mjs bypasses the
// token gate for this view only).

const VIEW_SUMMARY = [
  ["Choose", "pick a workflow pack to start from."],
  ["Canvas", "inspect the pack's DAG before you run it."],
  ["Connect", "review and authorize your own third-party services."],
  ["Run", "execute the workflow with live progress."],
  ["Verify", "check an evidence bundle offline, in this browser tab."],
  ["Review", "human sign-off on a run (Phase-2 stub)."],
  ["Operate", "daemon health, journal, anchors, backup."],
];

export async function renderHelp(root) {
  root.innerHTML = `
    <h2>Help</h2>

    <section class="card" aria-labelledby="help-views">
      <h3 id="help-views">What each tab does</h3>
      <dl class="verify-fence-list">
        ${VIEW_SUMMARY.map(([name, desc]) => `<div><dt>${name}</dt><dd>${desc}</dd></div>`).join("")}
      </dl>
    </section>

    <section class="card" aria-labelledby="help-loop">
      <h3 id="help-loop">What you can do</h3>
      <p>The core loop: pair with helmd &rarr; choose a pack &rarr; connect your services &rarr; run &rarr; verify &rarr; export evidence.</p>
    </section>

    <section class="card" aria-labelledby="help-connect">
      <h3 id="help-connect">Connecting your own services</h3>
      <p>Helm never proxies your data through ainumbers.co. Connectors run inside helmd on your machine and call your declared hosts directly — secrets stay in your OS keychain. Review a connector's host allowlist and scopes on the <a href="#/connect">Connect</a> view before authorizing it.</p>
    </section>

    <section class="card" aria-labelledby="help-pairing">
      <h3 id="help-pairing">Pairing / troubleshooting</h3>
      <p>"Not paired" means this browser tab has no token for talking to helmd — pairing tokens are per-tab and don't survive a closed tab or a restart, by design.</p>
      <p>To pair again:</p>
      <ol class="steps">
        <li>Open a terminal (Command Prompt or PowerShell on Windows, Terminal on macOS or Linux).</li>
        <li>Run <code>helmd start</code> to launch the daemon and open a freshly paired tab.</li>
        <li>If helmd is already running, run <code>helmd open</code> to get a new paired link for this browser.</li>
        <li>When it connects, the status pill at the top right reads "helmd connected".</li>
      </ol>
    </section>`;
}
