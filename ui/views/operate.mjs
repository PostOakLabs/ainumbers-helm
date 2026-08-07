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
  // §18.4: announce the idle-stop behavior wherever health is already shown,
  // not just at daemon boot — a tab opened hours after launch never sees the
  // console banner. Falls back silently on an older daemon with no field.
  const idleRow = data.idleTimeoutMs
    ? `<div class="field-row"><dt>Stops if idle</dt><dd>after ${Math.round(data.idleTimeoutMs / 1000)}s (Start Menu / Applications to relaunch)</dd></div>`
    : "";
  return `
    <dl>
      <div class="field-row"><dt>Status</dt><dd>${data.status}</dd></div>
      <div class="field-row"><dt>Uptime</dt><dd>${uptimeS}s</dd></div>
      ${idleRow}
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

// PROV-SNAP-HELM-1: the "helm UI shows chain-verify status" half of the
// row — data.verified reflects provenanceStatus()'s LIVE re-verification of
// the stored §HEAD-1 head chain (structural laws + each head's own
// eddsa-jcs-2022 proof), never a cached "it was signed once" claim.
function provenanceCard(data) {
  if (!data.has_chain) {
    return `<p class="empty-state">No state-snapshot chain yet — helmd emits the first one on its next boot.</p>`;
  }
  const status = data.verified ? "verified" : "FAILED";
  return `
    <dl>
      <div class="field-row"><dt>Chain-verify</dt><dd data-verified="${!!data.verified}">${status}</dd></div>
      <div class="field-row"><dt>Snapshot seq</dt><dd>${data.snapshot_seq}</dd></div>
      <div class="field-row"><dt>Head seq</dt><dd>${data.head_seq}</dd></div>
      ${data.errors?.length ? `<div class="field-row"><dt>Errors</dt><dd>${data.errors.join("; ")}</dd></div>` : ""}
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

// HELM-REPAIR-LINK-1: the pairing token lives in sessionStorage (P3-D9,
// api.mjs), so it's lost on tab close/browser restart, and 2026.8.4 stopped
// auto-opening a fresh tab on ordinary restarts (HELM-PAIR-DIAG-1) — this is
// the way back in. Mints a fresh #token= link over the ALREADY-authenticated
// bearer gate (POST /pair/relink), same durable token, a fresh single-use
// pairing nonce. Never console.log's the URL, never writes it into a log
// line or any persisted storage — clipboard only, with a manual-copy
// fallback (readonly input, value set as a DOM property, never interpolated
// into innerHTML) if clipboard access is blocked.
async function relink(port, token, root) {
  const resultEl = root.querySelector("#relink-result");
  resultEl.textContent = "Minting a fresh link…";
  const res = await call("/pair/relink", { port, token, method: "POST" });
  if (!res.ok) {
    resultEl.textContent =
      res.status === 404
        ? "Re-pairing links aren't available in this daemon version yet."
        : "helmd unreachable — link not minted.";
    return;
  }
  const url = res.data?.url;
  try {
    await navigator.clipboard.writeText(url);
    resultEl.textContent = "Copied to clipboard — keep it as private as a password. Paste it into a new tab if this one closes.";
  } catch {
    resultEl.innerHTML = `<label>Clipboard access blocked — select and copy by hand:<br><input type="text" readonly id="relink-url" style="width:100%"></label>`;
    const field = resultEl.querySelector("#relink-url");
    field.value = url;
    field.select();
  }
}

// HELM-UX-1 §8: lives here, not the header status pill — Unpair already
// sits there and two destructive-sounding buttons with very different
// consequences (Unpair just forgets a browser token; this stops the
// daemon process) next to each other is a footgun.
async function quitDaemon(port, token, resultEl) {
  resultEl.textContent = "Stopping helmd…";
  const res = await call("/shutdown", { port, token, method: "POST" });
  // HELM-AUTOSTART-1: this used to promise a restart at next login, which was
  // only ever true because first run installed a login entry without asking.
  // Autostart is opt-in now, so the honest instruction is "open Helm again".
  resultEl.textContent = res.ok
    ? "helmd stopped. Open Helm again when you need it."
    : "helmd unreachable — nothing was stopped.";
}

// HELM-AUTOSTART-1: the consent surface. helmd used to install a login entry
// and a Start Menu shortcut by itself on first run and print a console note
// about it — which the people this is built for never see, because they
// double-click a downloaded .exe and the window is gone. Both are now off
// until someone ticks a box here.
//
// State comes from GET /autostart on every render, never from localStorage:
// this box is a claim about what is on the machine right now, and a cached
// "on" for an entry a user removed by hand would be a lie about persistence,
// which is the one thing this card exists to stop.
function startupCardHtml() {
  return `
    <section class="card" aria-labelledby="op-startup">
      <h3 id="op-startup">Startup</h3>
      <p class="field-row-note">Both of these are off until you turn them on, and Quit or <code>helmd uninstall</code> removes them.</p>
      <p class="field-row">
        <label><input type="checkbox" id="autostart-toggle" disabled> Start Helm when I sign in</label>
      </p>
      <p class="field-row-note" id="autostart-where"></p>
      <p class="field-row">
        <label><input type="checkbox" id="shortcut-toggle" disabled> Add a Helm shortcut to this computer</label>
      </p>
      <p class="field-row-note" id="shortcut-where"></p>
      <p id="startup-result" role="status" aria-live="polite"></p>
    </section>`;
}

// textContent, not innerHTML: these strings are a registry path / filesystem
// path built from the user's own home directory, and a home directory can
// contain anything a filename can.
function applyStartupState(root, payload) {
  const auto = root.querySelector("#autostart-toggle");
  const shortcut = root.querySelector("#shortcut-toggle");
  const autoWhere = root.querySelector("#autostart-where");
  const shortcutWhere = root.querySelector("#shortcut-where");

  auto.checked = payload.autostart.installed === true;
  auto.disabled = payload.autostart.supported !== true;
  if (payload.autostart.supported !== true) {
    autoWhere.textContent = "Helm has no start-at-login entry for this operating system yet.";
  } else if (payload.autostart.stale) {
    autoWhere.textContent = `This entry no longer works: ${payload.autostart.location} points at a copy of Helm that is not there any more. Turn it off and on again to rewrite it.`;
  } else if (payload.autostart.installed) {
    autoWhere.textContent = `Written at ${payload.autostart.location}. Nothing here runs as administrator.`;
  } else {
    autoWhere.textContent = `Turning this on writes one per-user entry at ${payload.autostart.location}, which starts Helm at your next sign-in. Nothing here runs as administrator.`;
  }

  shortcut.checked = payload.shortcut.installed === true;
  shortcut.disabled = payload.shortcut.supported !== true;
  shortcutWhere.textContent =
    payload.shortcut.supported !== true
      ? "Helm has no shortcut to create on this operating system yet."
      : payload.shortcut.installed
        ? `Written at ${payload.shortcut.location}. It points at the Helm program, never at a pairing link.`
        : `Turning this on writes one file at ${payload.shortcut.location}. It points at the Helm program, never at a pairing link.`;
}

async function wireStartupCard(root, { port, token }) {
  const resultEl = root.querySelector("#startup-result");
  const initial = await call("/autostart", { port, token });
  if (!initial.ok) {
    resultEl.textContent =
      initial.status === 404
        ? "Startup options aren't available in this daemon version yet."
        : "helmd didn't answer — startup options can't be shown.";
    return;
  }
  applyStartupState(root, initial.data);

  const send = async (field, el) => {
    const wanted = el.checked;
    el.disabled = true;
    resultEl.textContent = "Saving…";
    const res = await call("/autostart", { port, token, method: "POST", body: { [field]: wanted } });
    el.disabled = false;
    if (!res.ok) {
      // Re-read rather than trusting the request: a refused write leaves the
      // machine in whatever state it was already in, not the state asked for.
      const after = await call("/autostart", { port, token });
      if (after.ok) applyStartupState(root, after.data);
      resultEl.textContent = "That didn't take effect — nothing was changed.";
      return;
    }
    applyStartupState(root, res.data);
    resultEl.textContent = wanted ? "Turned on." : "Turned off.";
  };

  root.querySelector("#autostart-toggle").addEventListener("change", (e) => send("autostart", e.target));
  root.querySelector("#shortcut-toggle").addEventListener("change", (e) => send("shortcut", e.target));
}

// SIGN-SEAM-1 / SIGNING-SURFACES-BUILD-SPEC.md §3, phil condition #5: the
// signer command IS key access, so pointing it at a new binary must go
// through an explicit human consent step, never a silent form submit. This
// is a two-click flow — "Review" renders exactly what is about to change
// (never submits anything), "Confirm and save" mints the consent ticket
// (POST /signer/config/ticket) and immediately spends it on the write (POST
// /signer/config) — same shape as the evidence-export consent tier.
function signerCardHtml() {
  return `
    <section class="card" aria-labelledby="op-signer">
      <h3 id="op-signer">External signer</h3>
      <p class="field-row-note">A command Helm runs to sign a digest — a PKCS#11 wrapper, a cloud-KMS CLI, a YubiKey tool. Helm never sees the private key; it only verifies what comes back.</p>
      <p id="signer-current" role="status" aria-live="polite">Checking…</p>
      <form id="signer-form">
        <p class="field-row"><label>Command (full path)<br><input type="text" id="signer-command" placeholder="/usr/local/bin/my-signer" required></label></p>
        <p class="field-row"><label>Arguments (one per line)<br><textarea id="signer-args" rows="2" placeholder="--slot&#10;1"></textarea></label></p>
        <p class="field-row"><label>Public key (SPKI DER, base64)<br><textarea id="signer-pubkey" rows="2" required></textarea></label></p>
        <button type="submit" id="signer-review-btn">Review</button>
      </form>
      <div id="signer-review" hidden>
        <p class="field-row-note">This replaces Helm's signing authority with the command below. Anything with access to this machine that can point Helm at a DIFFERENT command would gain the same authority — that is exactly what this confirmation step exists to require a human for.</p>
        <pre id="signer-review-summary"></pre>
        <button type="button" id="signer-confirm-btn">Confirm and save</button>
        <button type="button" id="signer-cancel-btn" class="secondary">Cancel</button>
      </div>
      <p id="signer-result" role="status" aria-live="polite"></p>
    </section>`;
}

function signerArgsFromTextarea(text) {
  return text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
}

async function wireSignerCard(root, { port, token }) {
  const currentEl = root.querySelector("#signer-current");
  const form = root.querySelector("#signer-form");
  const reviewEl = root.querySelector("#signer-review");
  const summaryEl = root.querySelector("#signer-review-summary");
  const resultEl = root.querySelector("#signer-result");

  const refreshCurrent = async () => {
    const res = await call("/signer/config", { port, token });
    if (!res.ok) {
      currentEl.textContent = res.status === 404 ? "External signers aren't available in this daemon version yet." : "helmd didn't answer.";
      return;
    }
    currentEl.textContent = res.data.config
      ? `Configured: ${res.data.config.command} (updated ${res.data.config.updatedAt})`
      : "Not configured — signing stays with Helm's own keys until you set one.";
  };
  await refreshCurrent();

  let pendingConfig = null;

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    pendingConfig = {
      command: root.querySelector("#signer-command").value.trim(),
      args: signerArgsFromTextarea(root.querySelector("#signer-args").value),
      algo: "ed25519",
      publicKeyDerBase64: root.querySelector("#signer-pubkey").value.trim(),
    };
    summaryEl.textContent = JSON.stringify(pendingConfig, null, 2);
    reviewEl.hidden = false;
    resultEl.textContent = "";
  });

  root.querySelector("#signer-cancel-btn").addEventListener("click", () => {
    pendingConfig = null;
    reviewEl.hidden = true;
  });

  root.querySelector("#signer-confirm-btn").addEventListener("click", async () => {
    if (!pendingConfig) return;
    resultEl.textContent = "Saving…";
    const ticketRes = await call("/signer/config/ticket", { port, token, method: "POST" });
    if (!ticketRes.ok) {
      resultEl.textContent = "helmd didn't answer — nothing was changed.";
      return;
    }
    const writeRes = await call("/signer/config", {
      port,
      token,
      method: "POST",
      body: { ticket: ticketRes.data.ticket, config: pendingConfig },
    });
    if (!writeRes.ok) {
      resultEl.textContent = "That didn't take effect — nothing was changed.";
      return;
    }
    reviewEl.hidden = true;
    pendingConfig = null;
    form.reset();
    resultEl.textContent = "Saved.";
    await refreshCurrent();
  });
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

  const [health, journal, anchors, provenance] = await Promise.all([
    fetchWithFallback("/health", { port, token }),
    fetchWithFallback("/journal/head", { port, token }),
    fetchWithFallback("/anchor/status", { port, token }),
    fetchWithFallback("/provenance/head", { port, token }),
  ]);

  const allBlocked = [health, journal, anchors, provenance].every((r) => classifyBlockedState(r));
  if (allBlocked) {
    const kind = classifyBlockedState(health) ?? classifyBlockedState(journal) ?? classifyBlockedState(anchors) ?? classifyBlockedState(provenance);
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
        <p class="field-row-note">The running log of everything Helm has recorded on this computer.</p>
        ${stateLine(journal, journalCard)}
      </section>
      <section class="card" aria-labelledby="op-anchor">
        <h3 id="op-anchor">Anchor status</h3>
        <p class="field-row-note">Whether the journal's history has been timestamped against an outside source, so it can't be quietly rewritten later.</p>
        ${stateLine(anchors, anchorCard)}
      </section>
      <section class="card" aria-labelledby="op-provenance">
        <h3 id="op-provenance">State-snapshot chain</h3>
        <p class="field-row-note">A tamper-check: each saved snapshot links to the one before it, so "Chain-verify: verified" means nothing in between was altered.</p>
        ${stateLine(provenance, provenanceCard)}
      </section>
      <section class="card" aria-labelledby="op-backup">
        <h3 id="op-backup">Backup</h3>
        <button type="button" id="backup-btn">Trigger backup</button>
        <p id="backup-result" role="status" aria-live="polite"></p>
      </section>
      ${startupCardHtml()}
      ${signerCardHtml()}
      <section class="card" aria-labelledby="op-relink">
        <h3 id="op-relink">Get back in from another tab</h3>
        <p class="field-row-note">This tab's pairing is remembered only for as long as it stays open. Mint a fresh link now and keep it somewhere safe — anyone who has it can open Helm as you.</p>
        <button type="button" id="relink-btn">Copy a fresh pairing link</button>
        <p id="relink-result" role="status" aria-live="polite"></p>
      </section>
      <section class="card" aria-labelledby="op-quit">
        <h3 id="op-quit">Quit Helm</h3>
        <p class="field-row-note">Stops helmd on this computer. This isn't a permanent uninstall — open Helm again, or turn on the startup option above and it comes back at your next sign-in.</p>
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
  root.querySelector("#relink-btn").addEventListener("click", () => {
    relink(port, token, root);
  });
  await wireStartupCard(root, { port, token });
  await wireSignerCard(root, { port, token });
}
