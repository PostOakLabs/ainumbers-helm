// Review view — Phase 2 stub (HELM-U3 row: "Review view ships as labeled
// Phase-2 stub only"). The review_task/review_decision/override schemas are
// already reserved-but-empty (HELM-S1); this view has nothing live to render
// until a Phase-2 WU builds the human-attestation workflow behind them.
export async function renderReview(root) {
  root.innerHTML = `
    <h2>Review <span class="phase-stub-badge">Phase 2</span></h2>
    <p class="empty-state">Human review and override workflows ship in a later Helm phase. The <code>review_task</code>, <code>review_decision</code>, and <code>override</code> object schemas are already reserved (SPEC.md §26.4) so this view can light up without a wire-format change — there is nothing to configure here yet.</p>`;
}
