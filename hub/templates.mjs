// Template gallery (HELM-P3-G10): curated compliance-scenario templates
// over the compiled pack catalog (HELM-P2-C1/U4) — kills the 400-kernel
// empty-canvas problem by pre-wiring a handful of named scenarios with
// real sample data and a one-click Run.
//
// A template is NOT a new pack. `packs/` is generator-owned
// (scripts/compile-packs.mjs --check rejects any file it didn't produce),
// so a template instead references an existing compiled pack by
// workflow_id and, at run time, injects sample `policy_parameters` into a
// deep clone of that pack's manifest — the file on disk never changes.
//
// sample_data values are copied verbatim from each kernel's committed
// fixtures (hub/vendored/ocg/kernels/fixtures/*.fixtures.json, the first
// passing vector) — never invented. Several kernels here are
// diagnostic/self-configuring and their golden vector is `{}`; that's the
// real default, not a placeholder.
import { getPack } from "./packs.mjs";

export const TEMPLATES = [
  {
    slug: "emir-field-check",
    title: "EMIR field check",
    blurb: "Validate an EMIR Refit auth.030 trade report's required fields, UTI format, and UPI classification before submission.",
    workflow_id: "pack-emir-trade-report-validation",
    sample_data: {
      n1: {
        report: {
          action_type: "New",
          reporting_counterparty_lei: "MAES062Z21O4RZ2U7M96",
          other_counterparty_lei: "7LTWFZYICNSX8D621K86",
          uti: "UTI-EXAMPLE-001-20240429",
          upi: "DJMM0VX7HY4A",
          notional: 1000000,
          notional_currency: "EUR",
          effective_date: "2024-04-29",
          asset_class: "IR",
        },
      },
      n2: { uti: "UTI001EXAMPLE2024042901", generating_party: "MAES062Z21O4RZ2U7M96", trade_unix: 1714348800, uti_shared_unix: 1714406400 },
      n3: { upi: "DJMM0VX7HY4A", asset_class: "IR", instrument_type: "IRS" },
    },
  },
  {
    slug: "reg-reporting-reconciliation",
    title: "Reg-reporting reconciliation",
    blurb: "Pair two counterparties' EMIR reports by UTI, reconcile fields within tolerance, and check lifecycle-event and reporting-readiness state.",
    workflow_id: "pack-emir-reconciliation-and-lifecycle",
    sample_data: {
      n1: {
        report_a: { uti: "UTI-TEST-001", notional: 1000000, asset_class: "IR" },
        report_b: { uti: "UTI-TEST-001", notional: 1000000, asset_class: "IR" },
        matching_fields: ["notional", "asset_class"],
        numeric_tolerance_pct: 1,
      },
      n2: { action_type: "New", prior_state: "none" },
      n3: { iso20022_cutover_done: true, upi_sourcing_configured: true, uti_sharing_sla_met: true, reconciliation_tolerance_set: true, lifecycle_action_controls: true },
    },
  },
  {
    slug: "sanctions-pre-screen",
    title: "Sanctions pre-screen",
    blurb: "Scope a firm's sanctions and export-control screening program and route to the right follow-on checks.",
    workflow_id: "pack-sanctions-fit",
    sample_data: { n1: {} },
  },
  {
    slug: "trade-lc-compliance",
    title: "Trade letter-of-credit compliance",
    blurb: "Check an LC presentation against eUCP/eURC/URDTT discrepancy rules, validate the commercial invoice, and verify cross-document provenance.",
    workflow_id: "pack-digital-trade-letter-of-credit",
    sample_data: { n1: {}, n2: {}, n3: {} },
  },
  {
    slug: "crypto-travel-rule",
    title: "Crypto travel-rule batch conformance",
    blurb: "Check originator/beneficiary field completeness on a transfer batch, including the unhosted-wallet branch, and verify its Merkle audit batch.",
    workflow_id: "pack-mica-travel-rule",
    sample_data: { n1: {}, n2: { proof_entries: [], merkle_root: "0000000000000000000000000000000000000000000000000000000000000000" } },
  },
];

export function listTemplates() {
  return TEMPLATES.map(({ slug, title, blurb, workflow_id }) => ({ slug, title, blurb, workflow_id }));
}

export function getTemplate(slug) {
  return TEMPLATES.find((t) => t.slug === slug) ?? null;
}

// Deep-clones the referenced pack's manifest and stamps each node's sample
// policy_parameters onto it. Node ids absent from sample_data pass through
// unchanged (compiled default, usually none). Returns null if the pack the
// template points at isn't in this build's compiled catalog.
export function buildTemplateManifest(template) {
  const pack = getPack(template.workflow_id);
  if (!pack) return null;
  const manifest = JSON.parse(JSON.stringify(pack.manifest));
  manifest.nodes = (manifest.nodes ?? []).map((node) => ({
    ...node,
    policy_parameters: template.sample_data?.[node.node_id] ?? node.policy_parameters ?? {},
  }));
  return manifest;
}
