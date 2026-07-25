// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Verify view (HELM-U3, SPEC.md §26.6-§26.8): full browser-side verification of
// an evidence bundle — DSSE dual-signature, entry/checkpoint self-consistency,
// anchor structural binding — with ZERO network access by default (§26.7).
// Standalone: works from a bundle file with no daemon running (this view never
// calls ../api.mjs). Legibility gate (§5.7): a reviewer unfamiliar with the code
// should be able to read what a trust label does and does NOT claim in under
// two minutes — the copy fence below is written for that reader, not for us.
import { verifyBundle, verifyAnchorBinding, verifyAnchorFull } from "../lib/verify-bundle.mjs";
import { renderPresenterHtml } from "../lib/presenter.mjs";
import { buildCommitteePackHtml } from "../lib/committee-pack.mjs";
import { buildCommitteeDeckSpec } from "../lib/committee-deck.mjs";
import { buildCommitteeDeckPptxBlob } from "../lib/committee-pptx.mjs";
import { DEMO_PUBLIC_KEYS, DEMO_GOLDEN_BUNDLE, DEMO_TAMPERED_BUNDLE } from "../fixtures/verify-demo.mjs";

const TRUST_LABEL_COPY = {
  hash_verified: "The artifact is unchanged relative to its stated preimage. Nothing here says the preimage itself was true.",
  kernel_verified: "A recorded deterministic kernel reproduced the recorded result from the recorded inputs. This does NOT mean the inputs were accurate — only that the computation over them is reproducible.",
  connector_asserted: "An authorized connector reported this payload at a point in time. There is NO claim that the payload's contents are true.",
  human_attested: "An identified authority reviewed, approved, or overrode a defined evidence package. This records a decision, not a guarantee the decision was correct.",
  external_ack_captured: "An external service returned this exact reference or receipt. There is NO claim about what that service did internally.",
};

function trustBadge(label) {
  const known = label in TRUST_LABEL_COPY;
  return `<span class="trust-badge" data-label="${known ? label : "unknown"}" title="${known ? TRUST_LABEL_COPY[label] : "Not one of the five §26.6 labels — a nonconformant producer, never treated as verified."}">${label}</span>`;
}

function statusBadge(ok, text) {
  // "partial" (F10): structurally bound but NOT a proof of authenticity —
  // never rendered as the same green "✓" a fully-checked item gets.
  const symbol = ok === "partial" ? "◐" : ok ? "✓" : "✗";
  return `<span class="verify-status" data-ok="${ok === "partial" ? "partial" : !!ok}">${symbol} ${text}</span>`;
}

function readFileAsJson(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        resolve(JSON.parse(reader.result));
      } catch (err) {
        reject(new Error(`not valid JSON: ${err.message}`));
      }
    };
    reader.onerror = () => reject(new Error("could not read file"));
    reader.readAsText(file);
  });
}

function renderEntries(entries) {
  if (!entries.length) return `<p class="empty-state">No entries in this bundle — there's nothing here to verify a signature or hash chain against.</p>`;
  return `<ul class="verify-entry-list">${entries
    .map(
      (e) => `
    <li class="verify-entry" data-ok="${e.valid}">
      ${statusBadge(e.valid, e.kind)}
      ${trustBadge(e.trust_label)}
      <code class="verify-digest">${e.digest}</code>
    </li>`
    )
    .join("")}</ul>`;
}

// The four independent RFC 3161 checks (HELM-TSA-1) as their own badges — never
// collapsed into one verdict, so a reader sees exactly which of {messageImprint,
// signature, chain-to-pinned-root, validity window} passed. An expired-but-
// validly-signed token and an untrusted-root token render as visibly DIFFERENT
// failures, not the same generic ✗.
function renderRfc3161FullBadges(full) {
  const rows = [
    ["messageImprint bound to this checkpoint", full.messageImprint],
    ["CMS signature verifies", full.signature],
    ["chains to a pinned TSA root", full.chain],
    ["genTime within certificate validity", full.validity],
  ];
  const items = rows
    .map(([label, r]) => {
      if (!r || !r.checked) return `<li>${statusBadge(null, `${label} — not checked${r?.reason ? ` (${r.reason})` : ""}`)}</li>`;
      const ok = "valid" in r ? r.valid : r.bound;
      const detail = r.reason ? ` — ${r.reason}` : r.rootName ? ` — root: ${r.rootName}` : "";
      return `<li>${statusBadge(!!ok, `${label}${detail}`)}</li>`;
    })
    .join("");
  const genTimeLine = full.genTime ? `<p class="verify-reason">TSA time: ${full.genTime}${full.policyOid ? ` (policy ${full.policyOid})` : ""} — a timestamp proves the digest existed at this time; it does NOT prove the document is correct.</p>` : "";
  return `<ul class="verify-anchor-list">${items}</ul>${genTimeLine}`;
}

function renderCheckpoints(checkpoints) {
  if (!checkpoints.length) return `<p class="empty-state">No checkpoints in this bundle — a checkpoint is a point where the run's evidence was anchored (timestamped or hash-chained); this evidence file doesn't have one.</p>`;
  return `<ul class="verify-entry-list">${checkpoints
    .map((cp, cpIdx) => {
      const anchorRows = (cp.predicate?.anchors ?? [])
        .map((a, aIdx) => {
          const b = verifyAnchorBinding(a, cp.predicate.journal_root_digest);
          const anchorId = `anchor-${cpIdx}-${aIdx}`;
          if (a.type === "rfc3161") {
            const text = b.checked
              ? b.bound
                ? `messageImprint bound to this checkpoint${b.genTime ? ` — TSA time ${b.genTime}` : ""} — checking signature, chain, and validity window…`
                : `NOT bound — ${b.reason ?? "messageImprint mismatch"}`
              : `structural check not applicable — ${b.reason}`;
            // A bound messageImprint alone only proves the token covers this
            // checkpoint's digest, not that the TSA's signature chains to a
            // trusted root — never render that case as an unqualified ✓ before
            // the fuller check (kicked off after this initial render, see
            // enhanceRfc3161Anchors) has actually run.
            const badgeOk = b.checked ? (b.bound ? "partial" : false) : null;
            return `<li id="${anchorId}" data-anchor-type="rfc3161">${statusBadge(badgeOk, `${a.type}: ${text}`)}</li>`;
          }
          if (a.type === "opentimestamps") {
            const text = b.checked
              ? b.digestBound
                ? `pending calendar attestation present, digest matches`
                : `NOT bound — ${b.reason}`
              : `structural check not applicable — ${b.reason}`;
            const pointer = b.upgradePointer
              ? `<p class="verify-reason">Not yet a Bitcoin block proof (Phase 1 scope). Upgrade pointer — check later, out of band: <code>${b.upgradePointer}</code></p>`
              : "";
            const badgeOk = b.checked && b.digestBound ? "partial" : b.checked ? false : null;
            return `<li data-anchor-type="opentimestamps">${statusBadge(badgeOk, `${a.type}: ${text}`)}${pointer}</li>`;
          }
          const text = b.checked ? (b.neutral ? `${b.status}${b.reason ? ` — ${b.reason}` : ""}` : b.bound ? "bound" : `NOT bound — ${b.reason ?? "mismatch"}`) : `structural check not applicable — ${b.reason}`;
          return `<li>${statusBadge(b.neutral ? null : b.checked ? !!b.bound : null, `${a.type}: ${text}`)}</li>`;
        })
        .join("");
      return `
    <li class="verify-entry" data-ok="${cp.valid}">
      ${statusBadge(cp.valid, `checkpoint #${cp.checkpointSeq}`)}
      <code class="verify-digest">${cp.digest}</code>
      ${cp.reason ? `<p class="verify-reason">${cp.reason}</p>` : ""}
      ${anchorRows ? `<ul class="verify-anchor-list">${anchorRows}</ul>` : ""}
    </li>`;
    })
    .join("")}</ul>`;
}

// Progressive enhancement (HELM-TSA-1): the initial render above is instant and
// zero-crypto-lib (structural messageImprint check only). AFTER that render,
// kick off the fuller signature+chain+validity check per rfc3161 anchor — it
// dynamic-imports the ~800KB pkijs bundle lazily (../lib/rfc3161-verify.mjs) —
// and replace each anchor's placeholder <li> in place once its verdict lands.
// Anchors resolve independently; one slow/failing anchor never blocks another's
// badge from updating.
function enhanceRfc3161Anchors(root, checkpoints) {
  checkpoints.forEach((cp, cpIdx) => {
    (cp.predicate?.anchors ?? []).forEach((a, aIdx) => {
      if (a.type !== "rfc3161") return;
      const li = root.querySelector(`#anchor-${cpIdx}-${aIdx}`);
      if (!li) return;
      verifyAnchorFull(a, cp.predicate.journal_root_digest)
        .then((full) => {
          const el = root.querySelector(`#anchor-${cpIdx}-${aIdx}`);
          if (!el || !full.full) return;
          el.innerHTML = renderRfc3161FullBadges(full.full);
        })
        .catch((err) => {
          const el = root.querySelector(`#anchor-${cpIdx}-${aIdx}`);
          if (el) el.innerHTML = `${statusBadge(false, `rfc3161: could not run the fuller offline check — ${err.message}`)}`;
        });
    });
  });
}

function downloadHtml(html, filename) {
  downloadBlob(new Blob([html], { type: "text/html" }), filename);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function runVerify(root, { bundle, publicKeys }) {
  const resultEl = root.querySelector("#verify-result");
  resultEl.innerHTML = `<p aria-live="polite">Verifying — nothing here leaves this browser tab.</p>`;
  let result;
  try {
    result = await verifyBundle(bundle, publicKeys);
  } catch (err) {
    resultEl.innerHTML = `<p class="verify-summary" data-ok="false">✗ Could not verify: ${err.message}</p>`;
    return;
  }
  resultEl.innerHTML = `
    ${renderPresenterHtml(bundle?.presenter)}
    <p class="verify-summary" data-ok="${result.valid}">
      ${result.valid ? "✓ Bundle verifies." : `✗ Bundle FAILS verification (${result.reasons.length} reason${result.reasons.length === 1 ? "" : "s"}).`}
    </p>
    ${result.reasons.length ? `<ul class="verify-reason-list">${result.reasons.map((r) => `<li>${r}</li>`).join("")}</ul>` : ""}
    <h3>Objects</h3>
    ${renderEntries(result.detail.entries)}
    <h3>Checkpoints</h3>
    ${renderCheckpoints(result.detail.checkpoints)}
    <p class="field-row">
      <button type="button" id="verify-export-committee-pack">Export Committee Pack (print to PDF)</button>
      <button type="button" id="verify-export-committee-deck" class="secondary">Export .pptx deck</button>
    </p>
    <p id="verify-deck-export-status" role="status" aria-live="polite"></p>`;
  enhanceRfc3161Anchors(root, result.detail.checkpoints);

  function checkpointsWithAnchorBinding() {
    return result.detail.checkpoints.map((cp) => {
      if (!cp.predicate) return cp;
      const anchors = (cp.predicate.anchors ?? []).map((a) => ({ ...a, binding: verifyAnchorBinding(a, cp.predicate.journal_root_digest) }));
      return { ...cp, predicate: { ...cp.predicate, anchors } };
    });
  }

  root.querySelector("#verify-export-committee-pack").addEventListener("click", () => {
    const html = buildCommitteePackHtml({
      bundle,
      entries: result.detail.entries,
      checkpoints: checkpointsWithAnchorBinding(),
      manifestDigest: bundle.manifest?.predicate?.workflow_manifest_digest,
      generatedAt: new Date().toISOString(),
    });
    downloadHtml(html, `committee-pack-${bundle.manifest?.predicate?.bundle_id ?? "export"}.html`);
  });

  root.querySelector("#verify-export-committee-deck").addEventListener("click", async () => {
    const statusEl = root.querySelector("#verify-deck-export-status");
    statusEl.textContent = "Building deck — nothing leaves this browser tab…";
    try {
      const spec = buildCommitteeDeckSpec({
        bundle,
        entries: result.detail.entries,
        checkpoints: checkpointsWithAnchorBinding(),
        manifestDigest: bundle.manifest?.predicate?.workflow_manifest_digest,
        generatedAt: new Date().toISOString(),
      });
      const blob = await buildCommitteeDeckPptxBlob(spec);
      downloadBlob(blob, `committee-deck-${bundle.manifest?.predicate?.bundle_id ?? "export"}.pptx`);
      statusEl.textContent = "Deck downloaded — macro-free OOXML, no network access used.";
    } catch (err) {
      statusEl.textContent = `Could not build deck: ${err.message}`;
    }
  });
}

// HELM-P4-J5: fetch-by-URL half of `#load=<https-url>` link opening. Same
// graceful-failure doctrine as company-profile.mjs's config fetch — an
// unreachable host, non-200, or non-JSON body just leaves the bundle slot
// empty with an error message, never a thrown error out of renderVerify.
// https-only (no file://, no javascript:) by construction of the regex.
async function fetchBundleFromUrl(url) {
  if (!/^https:\/\//.test(url)) throw new Error("bundle link must be an https:// URL");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch failed: HTTP ${res.status}`);
  return res.json();
}

function wireInputs(root, { loadUrl } = {}) {
  const state = { bundle: null, publicKeys: null };
  const bundleFile = root.querySelector("#verify-bundle-file");
  const bundlePaste = root.querySelector("#verify-bundle-paste");
  const keysFile = root.querySelector("#verify-keys-file");
  const keysPaste = root.querySelector("#verify-keys-paste");
  const runBtn = root.querySelector("#verify-run-btn");
  const loadState = root.querySelector("#verify-load-state");

  function setBundle(obj, label) {
    state.bundle = obj;
    loadState.querySelector("#verify-bundle-state").textContent = label;
    updateRunEnabled();
  }
  function setKeys(obj, label) {
    state.publicKeys = obj;
    loadState.querySelector("#verify-keys-state").textContent = label;
    updateRunEnabled();
  }
  function updateRunEnabled() {
    runBtn.disabled = !(state.bundle && state.publicKeys);
  }

  bundleFile.addEventListener("change", async () => {
    const file = bundleFile.files[0];
    if (!file) return;
    try {
      setBundle(await readFileAsJson(file), `loaded ${file.name}`);
    } catch (err) {
      setBundle(null, `error: ${err.message}`);
    }
  });
  bundlePaste.addEventListener("change", () => {
    if (!bundlePaste.value.trim()) return;
    try {
      setBundle(JSON.parse(bundlePaste.value), "loaded from pasted text");
    } catch (err) {
      setBundle(null, `error: ${err.message}`);
    }
  });
  keysFile.addEventListener("change", async () => {
    const file = keysFile.files[0];
    if (!file) return;
    try {
      setKeys(await readFileAsJson(file), `loaded ${file.name}`);
    } catch (err) {
      setKeys(null, `error: ${err.message}`);
    }
  });
  keysPaste.addEventListener("change", () => {
    if (!keysPaste.value.trim()) return;
    try {
      setKeys(JSON.parse(keysPaste.value), "loaded from pasted text");
    } catch (err) {
      setKeys(null, `error: ${err.message}`);
    }
  });

  root.querySelector("#verify-demo-golden-btn").addEventListener("click", () => {
    setBundle(DEMO_GOLDEN_BUNDLE, "loaded built-in golden demo");
    setKeys(DEMO_PUBLIC_KEYS, "loaded built-in demo identity");
    runVerify(root, { bundle: state.bundle, publicKeys: state.publicKeys });
  });
  root.querySelector("#verify-demo-tampered-btn").addEventListener("click", () => {
    setBundle(DEMO_TAMPERED_BUNDLE, "loaded built-in TAMPERED demo");
    setKeys(DEMO_PUBLIC_KEYS, "loaded built-in demo identity");
    runVerify(root, { bundle: state.bundle, publicKeys: state.publicKeys });
  });
  runBtn.addEventListener("click", () => runVerify(root, { bundle: state.bundle, publicKeys: state.publicKeys }));

  if (loadUrl) {
    setBundle(null, `loading from link…`);
    fetchBundleFromUrl(loadUrl)
      .then((obj) => setBundle(obj, "loaded from shared link"))
      .catch((err) => setBundle(null, `error loading link: ${err.message}`));
  }
}

export async function renderVerify(root, { params } = {}) {
  const loadUrl = params?.get("load") || null;
  root.innerHTML = `
    <p class="field-row-note">Checks an evidence bundle entirely in this browser tab. Nothing is uploaded, and no daemon connection is required.</p>
    ${loadUrl ? `<p class="field-row-note" data-testid="verify-link-notice">Opened from a shared bundle link. Public identity/keys still need to be loaded separately — Helm has no key registry.</p>` : ""}

    <section class="card verify-copy-fence" aria-labelledby="verify-what-checked">
      <h3 id="verify-what-checked">What this checks — and what it does not</h3>
      <dl class="verify-fence-list">
        <div><dt>✓ Checked</dt><dd>Every object's DSSE envelope: Ed25519 signature (required) and ML-DSA-44 signature (checked whenever present — a tampered post-quantum co-signature fails even though it's optional). Every entry's digest, kind, and trust label match the signed manifest exactly. Redaction: no secret-shaped fields are present in the exported predicate. Each checkpoint's declared running-hash state is internally self-consistent. RFC 3161 anchors, as four independent checks: the token's message imprint is bound to the checkpoint it claims to cover; the CMS signature verifies against the embedded signer certificate; that certificate chains to a PINNED TSA root (DigiCert, Sectigo, or FreeTSA — never a root the token itself supplies); and the TSA's claimed time falls inside the signing certificate's validity window. All four run fully offline.</dd>
        <div><dt>✗ NOT checked</dt><dd>Whether the underlying real-world event is true — a trust label never claims that (see below), and a timestamp proves only that a digest existed at a given time, never that the document is correct. Whether an OpenTimestamps anchor has been upgraded to a Bitcoin block proof — Phase 1 captures only the pending calendar attestation plus a pointer for checking the upgrade later, out of band. Whether this checkpoint's state still matches a LIVE daemon's journal — this view has none; the Operate view checks that when a daemon is reachable.</dd>
      </dl>
    </section>

    <section class="card" aria-labelledby="verify-trust-labels">
      <h3 id="verify-trust-labels">Trust label vocabulary (SPEC.md §26.6)</h3>
      <dl class="verify-fence-list">
        ${Object.entries(TRUST_LABEL_COPY).map(([label, copy]) => `<div><dt>${trustBadge(label)}</dt><dd>${copy}</dd></div>`).join("")}
      </dl>
    </section>

    <section class="card" aria-labelledby="verify-load">
      <h3 id="verify-load">Load a bundle</h3>
      <p class="field-row-note"><button type="button" id="verify-demo-golden-btn">Try the built-in demo (golden)</button> <button type="button" id="verify-demo-tampered-btn" class="secondary">Try the built-in demo (tampered — proven to fail)</button></p>
      <div class="verify-load-grid">
        <div>
          <label for="verify-bundle-file">Evidence bundle (.json)</label>
          <input type="file" id="verify-bundle-file" accept="application/json" />
          <label for="verify-bundle-paste">…or paste bundle JSON</label>
          <textarea id="verify-bundle-paste" rows="3"></textarea>
        </div>
        <div>
          <label for="verify-keys-file">Producer identity / public keys (.json)</label>
          <input type="file" id="verify-keys-file" accept="application/json" />
          <label for="verify-keys-paste">…or paste identity JSON</label>
          <textarea id="verify-keys-paste" rows="3"></textarea>
          <p class="field-row-note">Helm has no key registry (verify-only doctrine) — get this from your Helm operator out-of-band. Shape: <code>{"ed25519SpkiB64": "…", "mldsa44B64": "…"}</code>.</p>
        </div>
      </div>
      <p id="verify-load-state" role="status" aria-live="polite">
        Bundle: <span id="verify-bundle-state">none loaded</span> · Identity: <span id="verify-keys-state">none loaded</span>
      </p>
      <button type="button" id="verify-run-btn" disabled>Verify</button>
    </section>

    <section id="verify-result" class="card" aria-live="polite" aria-labelledby="verify-load"></section>`;

  wireInputs(root, { loadUrl });
}
