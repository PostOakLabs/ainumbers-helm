// Presenter co-brand block (HELM-P4-J2, HELM-PHASE4-BUILD-SPEC.md §2 Band D
// row J2): an optional, UNSIGNED sibling field on the bundle object
// (bundle.presenter) — outside manifest/objects/checkpoints, so it never
// enters anything verifyBundle() checks (see hub/bundle.mjs, ui/lib/verify-bundle.mjs).
// Swapping or stripping it can never change a verification result — see
// presenter.test.mjs's tampered-swap fixture. Rendered by both the in-app
// Verify view (ui/views/verify.mjs) and the embedded offline verifier
// (ui/lib/standalone-verifier.mjs) via this one shared helper, always in a
// clearly separate "Presented by" section so it can't be mistaken for
// verified content, and never inside the verifier's own origin/hash/version
// footer.
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const LOGO_DATA_URI_RE = /^data:image\/(png|jpeg|svg\+xml|webp);base64,/;

// Schema-shaped validator mirroring schema/presenter.schema.json — kept as a
// plain function (not schema-validator.mjs) since this also runs inside the
// zero-dependency standalone verifier build.
export function isValidPresenter(presenter) {
  if (presenter == null) return true;
  if (typeof presenter !== "object" || Array.isArray(presenter)) return false;
  if (typeof presenter.name !== "string" || !presenter.name.trim()) return false;
  if (presenter.logo !== undefined && (typeof presenter.logo !== "string" || !LOGO_DATA_URI_RE.test(presenter.logo))) return false;
  if (presenter.statement !== undefined && typeof presenter.statement !== "string") return false;
  return true;
}

export function renderPresenterHtml(presenter) {
  if (!presenter || !isValidPresenter(presenter) || !presenter.name) return "";
  return `
<section class="presenter-block" aria-labelledby="presenter-heading" data-presenter="true">
  <p id="presenter-heading" class="presenter-label">Presented by <span class="presenter-caveat">(not part of the verified evidence)</span></p>
  <div class="presenter-card">
    ${presenter.logo ? `<img class="presenter-logo" src="${esc(presenter.logo)}" alt="${esc(presenter.name)} logo" />` : ""}
    <span class="presenter-name">${esc(presenter.name)}</span>
    ${presenter.statement ? `<p class="presenter-statement">${esc(presenter.statement)}</p>` : ""}
  </div>
</section>`;
}
