// Verify view (HELM-U3, SPEC.md §26.6-§26.8): full browser-side verification of
// an evidence bundle — DSSE dual-signature, entry/checkpoint self-consistency,
// anchor structural binding — with ZERO network access by default (§26.7).
// Standalone: works from a bundle file with no daemon running (this view never
// calls ../api.mjs). Legibility gate (§5.7): a reviewer unfamiliar with the code
// should be able to read what a trust label does and does NOT claim in under
// two minutes — the copy fence below is written for that reader, not for us.
import { verifyBundle, verifyAnchorBinding } from "../lib/verify-bundle.mjs";
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
  return `<span class="verify-status" data-ok="${!!ok}">${ok ? "✓" : "✗"} ${text}</span>`;
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
  if (!entries.length) return `<p class="empty-state">No entries.</p>`;
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

function renderCheckpoints(checkpoints) {
  if (!checkpoints.length) return `<p class="empty-state">No checkpoints in this bundle.</p>`;
  return `<ul class="verify-entry-list">${checkpoints
    .map((cp) => {
      const anchorRows = (cp.predicate?.anchors ?? [])
        .map((a) => {
          const b = verifyAnchorBinding(a, cp.predicate.journal_root_digest);
          const text = b.checked
            ? b.bound
              ? `bound to this checkpoint${b.genTime ? ` — TSA time ${b.genTime}` : ""}`
              : `NOT bound — ${b.reason ?? "messageImprint mismatch"}`
            : `structural check not applicable — ${b.reason}`;
          return `<li>${statusBadge(b.checked ? b.bound : null, `${a.type}: ${text}`)}</li>`;
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
    <p class="verify-summary" data-ok="${result.valid}">
      ${result.valid ? "✓ Bundle verifies." : `✗ Bundle FAILS verification (${result.reasons.length} reason${result.reasons.length === 1 ? "" : "s"}).`}
    </p>
    ${result.reasons.length ? `<ul class="verify-reason-list">${result.reasons.map((r) => `<li>${r}</li>`).join("")}</ul>` : ""}
    <h3>Objects</h3>
    ${renderEntries(result.detail.entries)}
    <h3>Checkpoints</h3>
    ${renderCheckpoints(result.detail.checkpoints)}`;
}

function wireInputs(root) {
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
}

export async function renderVerify(root) {
  root.innerHTML = `
    <h2>Verify</h2>
    <p class="field-row-note">Checks an evidence bundle entirely in this browser tab. Nothing is uploaded, and no daemon connection is required.</p>

    <section class="card verify-copy-fence" aria-labelledby="verify-what-checked">
      <h3 id="verify-what-checked">What this checks — and what it does not</h3>
      <dl class="verify-fence-list">
        <div><dt>✓ Checked</dt><dd>Every object's DSSE envelope: Ed25519 signature (required) and ML-DSA-44 signature (checked whenever present — a tampered post-quantum co-signature fails even though it's optional). Every entry's digest, kind, and trust label match the signed manifest exactly. Redaction: no secret-shaped fields are present in the exported predicate. Each checkpoint's declared running-hash state is internally self-consistent. RFC 3161 anchors: the token's message imprint is bound to the checkpoint it claims to cover.</dd>
        <div><dt>✗ NOT checked</dt><dd>Whether the underlying real-world event is true — a trust label never claims that (see below). The TSA certificate's chain of trust to a root authority. Whether an OpenTimestamps anchor has been upgraded to a Bitcoin block proof (Phase 1 only captures the pending calendar attestation). Whether this checkpoint's state still matches a LIVE daemon's journal — this view has none; the Operate view checks that when a daemon is reachable.</dd>
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

  wireInputs(root);
}
