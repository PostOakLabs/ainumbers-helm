// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Operate view: daemon health, journal head, anchor status, backup trigger.
// Journal/anchor/backup ship with HELM-H3; the calls below are already wired
// so this view lights up with no UI changes once that daemon route lands.
import { fetchWithFallback, call } from "../api.mjs";
import { blockedStateHtml, classifyBlockedState } from "../lib/blocked-state.mjs";
import { pairFormHtml, wirePairForm } from "../lib/pair-form.mjs";

function stateLine(result, render) {
  if (result.state === "live") return render(result.data);
  if (result.state === "stale") {
    return `${render(result.data)}<span class="stale-badge" role="status">stale — last seen ${result.at}</span>`;
  }
  const blocked = classifyBlockedState(result);
  return blockedStateHtml(blocked, { status: result.status, route: result.route });
}

function healthCard(data) {
  const uptimeS = Math.round((data.uptimeMs ?? 0) / 1000);
  return `
    <dl>
      <div class="field-row"><dt>Status</dt><dd>${data.status}</dd></div>
      <div class="field-row"><dt>Uptime</dt><dd>${uptimeS}s</dd></div>
    </dl>`;
}

function journalCard(data) {
  return `
    <dl>
      <div class="field-row"><dt>Stream</dt><dd>${data.stream_id}</dd></div>
      <div class="field-row"><dt>Journal seq</dt><dd>${data.journal_seq}</dd></div>
      <div class="field-row"><dt>Running hash</dt><dd>${data.rh}</dd></div>
    </dl>`;
}

function anchorCard(data) {
  const anchors = data.anchors ?? [];
  if (anchors.length === 0) return `<p class="empty-state">No anchors recorded yet.</p>`;
  return `<ul>${anchors.map((a) => `<li>${a.type} — ${a.log_origin ?? "pending"}</li>`).join("")}</ul>`;
}

async function runBackup(port, token, resultEl) {
  resultEl.textContent = "Requesting backup…";
  const res = await call("/backup", { port, token, method: "POST" });
  if (res.ok) {
    resultEl.textContent = `Backup complete: ${res.data?.archive_path ?? "archive written"}.`;
  } else if (res.status === 404) {
    resultEl.textContent = "Backup isn't available in this daemon version yet.";
  } else {
    resultEl.textContent = `helmd unreachable — backup not run.`;
  }
}

// HELM-UX-1 §8: lives here, not the header status pill — Unpair already
// sits there and two destructive-sounding buttons with very different
// consequences (Unpair just forgets a browser token; this stops the
// daemon process) next to each other is a footgun.
async function quitDaemon(port, token, resultEl) {
  resultEl.textContent = "Stopping helmd…";
  const res = await call("/shutdown", { port, token, method: "POST" });
  resultEl.textContent = res.ok
    ? "helmd stopped. It restarts automatically the next time you log in."
    : "helmd unreachable — nothing was stopped.";
}

// Persona starter presets (LANDING §3.1 borrow) — curated preview of what
// Operate shows once helmd is running, so the dormant state has a home
// screen instead of a wall of empty cards.
const PERSONAS = [
  {
    name: "Compliance officer",
    blurb: "Journal head, anchor status, and backup history for audit review.",
  },
  {
    name: "Trader",
    blurb: "Live daemon health and the running hash for a fast pass/fail check.",
  },
  {
    name: "Deal team",
    blurb: "Anchor status per document set, with backup as the paper trail.",
  },
];

function personaCard(persona) {
  return `
    <section class="card" aria-labelledby="persona-${persona.name.replace(/\s+/g, "-").toLowerCase()}">
      <h3 id="persona-${persona.name.replace(/\s+/g, "-").toLowerCase()}">${persona.name}</h3>
      <p class="empty-state">${persona.blurb}</p>
    </section>`;
}

// §11.1: this page could not have loaded without helmd already serving it,
// so "helmd isn't running" is never the real cause here — it's this tab's
// token, or a route this Helm version doesn't have yet. §13.4: the only
// terminal-command escape hatch allowed on this view is the collapsed
// "pair this tab by hand" form below, reusing app.mjs's shell-level form.
function dormantHome(kind, port) {
  return `
    ${blockedStateHtml(kind, {
      port,
      extra: `
        <details class="disclosure">
          <summary>Advanced: pair this tab by hand</summary>
          ${pairFormHtml()}
        </details>`,
    })}
    <div class="card-grid">
      ${PERSONAS.map(personaCard).join("")}
    </div>`;
}

export async function renderOperate(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Checking helmd…</p>`;

  const [health, journal, anchors] = await Promise.all([
    fetchWithFallback("/health", { port, token }),
    fetchWithFallback("/journal/head", { port, token }),
    fetchWithFallback("/anchor/status", { port, token }),
  ]);

  const allBlocked = [health, journal, anchors].every((r) => classifyBlockedState(r));
  if (allBlocked) {
    const kind = classifyBlockedState(health) ?? classifyBlockedState(journal) ?? classifyBlockedState(anchors);
    root.innerHTML = dormantHome(kind, port);
    wirePairForm(root, () => renderOperate(root, { port, token }));
    return;
  }

  root.innerHTML = `
    <div class="card-grid">
      <section class="card" aria-labelledby="op-health">
        <h3 id="op-health">Daemon health</h3>
        ${stateLine(health, healthCard)}
      </section>
      <section class="card" aria-labelledby="op-journal">
        <h3 id="op-journal">Journal head</h3>
        ${stateLine(journal, journalCard)}
      </section>
      <section class="card" aria-labelledby="op-anchor">
        <h3 id="op-anchor">Anchor status</h3>
        ${stateLine(anchors, anchorCard)}
      </section>
      <section class="card" aria-labelledby="op-backup">
        <h3 id="op-backup">Backup</h3>
        <button type="button" id="backup-btn">Trigger backup</button>
        <p id="backup-result" role="status" aria-live="polite"></p>
      </section>
      <section class="card" aria-labelledby="op-quit">
        <h3 id="op-quit">Quit Helm</h3>
        <p class="field-row-note">Stops helmd on this computer. Autostart brings it back at your next login — this isn't a permanent uninstall.</p>
        <button type="button" id="quit-btn" class="secondary">Quit Helm</button>
        <p id="quit-result" role="status" aria-live="polite"></p>
      </section>
    </div>`;

  root.querySelector("#backup-btn").addEventListener("click", () => {
    runBackup(port, token, root.querySelector("#backup-result"));
  });
  root.querySelector("#quit-btn").addEventListener("click", () => {
    quitDaemon(port, token, root.querySelector("#quit-result"));
  });
}
