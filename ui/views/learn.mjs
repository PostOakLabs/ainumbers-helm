// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Learn view (HELM-UX2-D-VIEWS, HELM-UX-BUILD-SPEC.md §12.8): renamed from
// help.mjs. Static explainer, no daemon dependency — renders even when the
// browser has no pairing token, so it's reachable from the "not paired"
// welcome state (app.mjs bypasses the token gate for this view).
//
// §12.8: VIEW_SUMMARY (the old hand-written tab list, which had drifted to
// 7 of 9 tabs and still called Review a "Phase-2 stub") is DELETED — the
// list below maps over TABS, the single source of truth (§12), so it cannot
// drift again. Learn also absorbs the doc links, the one estate surface
// with no in-app home (§12.8), and is one of the two views §13.4 permits a
// terminal command in — collapsed, never in the primary message.
//
// §17.4: the "install Helm for the first time" copy below (signing status,
// OS warning wording) is the SSOT for that wording — mirrored in
// repo/helm.html's #quickstart section. Any change here ships with a
// matching change there in the same wave.
import { TABS } from "../lib/tab-meta.mjs";

const DOC_LINKS = [
  ["Whitepaper", "https://ainumbers.co/chaingraph/openchain-graph-paper.html"],
  ["OpenChainGraph standard", "https://ainumbers.co/chaingraph/openchain-graph-spec.html"],
  ["Getting started docs", "https://ainumbers.co/start.html"],
  ["Education Hub", "https://ainumbers.co/chaingraph/education-hub.html"],
  ["Guides", "https://ainumbers.co/guides/index.html"],
];

export async function renderLearn(root) {
  root.innerHTML = `
    <section class="card" aria-labelledby="learn-tabs">
      <h3 id="learn-tabs">What each tab does</h3>
      <dl class="verify-fence-list">
        ${TABS.map((t) => `<div><dt>${t.label}</dt><dd>${t.intro}</dd></div>`).join("")}
      </dl>
    </section>

    <section class="card" aria-labelledby="learn-loop">
      <h3 id="learn-loop">What you can do</h3>
      <p>The core loop: pair with helmd &rarr; choose a pack &rarr; connect your services &rarr; run &rarr; verify &rarr; export evidence.</p>
    </section>

    <section class="card" aria-labelledby="learn-connect">
      <h3 id="learn-connect">Connecting your own services</h3>
      <p>Helm never proxies your data through ainumbers.co. Connectors run inside helmd on your machine and call your declared hosts directly — secrets stay in your OS keychain. Review a connector's host allowlist and scopes on the <a href="#/connect">Connect</a> view before authorizing it.</p>
    </section>

    <section class="card" aria-labelledby="learn-pairing">
      <h3 id="learn-pairing">Get back in when a tab says it isn't connected</h3>
      <p>Helm's connection to a browser tab only lasts as long as that tab does — closing it, restarting your browser, or opening an old bookmark all lose it. That's expected, by design, not a bug: nothing you did wrong, and none of your data or evidence is affected.</p>
      <ol class="steps">
        <li><strong>Check whether Helm is even open.</strong> Look in your login items, Start menu, dock, or taskbar. If it isn't there, open it — a connected browser tab opens on its own.</li>
        <li><strong>Still have a Helm tab open somewhere else?</strong> Switch back to that tab — a connection only works in the tab it started in, so a different or older tab won't pick it up.</li>
        <li><strong>Helm is running, but every tab is gone?</strong> Reopen Helm from wherever you launched it before (login items, Start menu, applications folder) — that opens a fresh, already-connected tab rather than resuming an old one.</li>
        <li><strong>Still stuck?</strong> Use <a href="#/operate">Status</a>'s "Advanced: pair by hand" form, or the same form on the connection screen itself, with a fresh pairing link from Helm.</li>
      </ol>
      <p>Helm doesn't run at sign-in unless you turned that on yourself, on <a href="#/operate">Status</a>.</p>
      <details class="disclosure">
        <summary>Advanced: start Helm from a command line</summary>
        <p>If Helm isn't set to start automatically, or you're on a machine without it installed yet:</p>
        <ol class="steps">
          <li>Open a terminal (Command Prompt or PowerShell on Windows, Terminal on macOS or Linux).</li>
          <li>Run <code>helmd start</code> to launch the daemon and open a freshly paired tab.</li>
          <li>If helmd is already running, run <code>helmd open</code> to get a new paired link for this browser.</li>
        </ol>
        <p>Haven't downloaded helmd yet? Get it from the public repo's <a href="https://github.com/PostOakLabs/ainumbers-helm/releases/latest" rel="noopener">releases page</a>. Windows and macOS builds aren't code-signed yet, so your OS may show a warning the first time you run one — Windows may say "Windows protected your PC", macOS may say the developer cannot be verified. Don't click past a warning like that on trust alone: check the file's SHA-256 against the signed release manifest first, and wait rather than override your OS's protection if you're not confident. Steps for that check are in <a href="https://ainumbers.co/helm.html#quickstart" rel="noopener">the quickstart's "Verify your download" section</a>. No signing step on Linux.</p>
      </details>
    </section>

    <section class="card" aria-labelledby="learn-docs">
      <h3 id="learn-docs">Read more</h3>
      <ul>
        ${DOC_LINKS.map(([label, href]) => `<li><a href="${href}" rel="noopener">${label}</a></li>`).join("")}
      </ul>
    </section>`;
}
