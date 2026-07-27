// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Home view (HELM-UX2-D-VIEWS, HELM-UX-BUILD-SPEC.md §12.6/§12.8): the
// default route, standalone in nav, requiresPairing: false — it must render
// identically whether or not helmd has answered yet. §0.3 still binds: this
// is NOT a splash and must never be framed as covering first-run latency —
// it is a permanent destination a returning user lands on too, not a
// one-time loading screen. It therefore carries no daemon call and no
// "connecting…" copy; the status pill in the header already owns that.

const STEPS = [
  ["Choose a workflow", "Pick a ready-made template or one of your own packs on <a href=\"#/choose\">Choose</a>."],
  ["Review before you run it", "Canvas shows the exact steps a workflow will take, and Connect shows which services it can reach."],
  ["Run it and watch", "Run streams live progress; anything needing a person to sign off shows up on Review."],
  ["Keep the evidence", "Verify checks an evidence file's signatures offline, any time, on any machine."],
];

export async function renderHome(root) {
  root.innerHTML = `
    <section class="card" aria-labelledby="home-what">
      <h3 id="home-what">What Helm is</h3>
      <p>Helm runs compliance and audit workflows on this computer — your data and credentials stay local, and every run produces a signed evidence file you can hand to an examiner without a network connection.</p>
    </section>

    <section class="card" aria-labelledby="home-first">
      <h3 id="home-first">What to do first</h3>
      <ol class="steps">
        ${STEPS.map(([title, body]) => `<li><strong>${title}.</strong> ${body}</li>`).join("")}
      </ol>
    </section>

    <section class="card" aria-labelledby="home-startup">
      <h3 id="home-startup">Helm only runs when you open it</h3>
      <p>Nothing is added to this computer's startup items unless you ask for it. If you want Helm running after you sign in, the switch is on <a href="#/operate">Operate</a>.</p>
    </section>

    <section class="card" aria-labelledby="home-more">
      <h3 id="home-more">Want more detail?</h3>
      <p>See <a href="#/learn">Learn</a> for how each tab works, or <a href="#/deadlines">Deadlines</a> for the regulatory dates your workflows cover.</p>
    </section>`;
}
