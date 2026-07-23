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

export async function renderOperate(root, { port, token }) {
  root.innerHTML = `<p aria-live="polite">Checking helmd…</p>`;

  const [health, journal, anchors] = await Promise.all([
    fetchWithFallback("/health", { port, token }),
    fetchWithFallback("/journal/head", { port, token }),
    fetchWithFallback("/anchor/status", { port, token }),
  ]);

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
