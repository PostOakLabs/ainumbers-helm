// Operate view: daemon health, journal head, anchor status, backup trigger.
// Journal/anchor/backup ship with HELM-H3; the calls below are already wired
// so this view lights up with no UI changes once that daemon route lands.
import { fetchWithFallback, call } from "../api.mjs";

function stateLine(result, render) {
  if (result.state === "live") return render(result.data);
  if (result.state === "stale") {
    return `${render(result.data)}<span class="stale-badge" role="status">stale — last seen ${result.at}</span>`;
  }
  if (result.state === "unavailable") return `<p class="unavailable-state">Not available in this daemon version yet.</p>`;
  return `<p class="empty-state">helmd unreachable.</p>`;
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

function dormantHome() {
  return `
    <h2>Operate</h2>
    <p class="empty-state">helmd isn't running yet. Start it with <code>helmd start</code> — these cards fill in once it's connected.</p>
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

  const allMissing = [health, journal, anchors].every((r) => r.state === "missing");
  if (allMissing) {
    root.innerHTML = dormantHome();
    return;
  }

  root.innerHTML = `
    <h2>Operate</h2>
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
    </div>`;

  root.querySelector("#backup-btn").addEventListener("click", () => {
    runBackup(port, token, root.querySelector("#backup-result"));
  });
}
