// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Private-input witness sourcing for OCG Standard §25 ocg-private-input@1 kernels
// (PACKPARITY-WITNESS-1). compile-parity-gate.mjs samples each node's input from its
// kernel's <tool_id>.fixtures.json — but a §25 node's fixture policy_parameters carries
// ONLY the sha256-salted@1 commitment (per §25.2's plaintext-exclusion rule), never the
// private figures buildArtifact() actually needs as its first argument. This module
// reconstructs that argument from the matching OUT-OF-BAND <tool_id>.disclosure.json
// fixture (salt + plaintext, test-only, never shipped as a live artifact field — see
// SPEC.md §25 "Salt handling") and SELF-VERIFIES the result before returning it.
//
// Each assembler below is a small, explicit map from one kernel's disclosure input_value
// shape to its buildArtifact() raw witness shape (documented in that kernel's own
// buildArtifact doc-comment) — deliberately NOT a generic structural guess. The private
// witness shape differs kernel to kernel (a flat spread for art-529, a single named array
// for art-413, a named sub-object alongside sibling public fields for art-414/415), and a
// wrong guess would corrupt the very sha256-salted@1 commitment this exists to verify.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const ASSEMBLERS = {
  // art-413-screen-sanctions-private.kernel.mjs buildArtifact(raw):
  //   raw = { parties, salt, list_version?, matching_config? }
  "art-413-screen-sanctions-private": (publicParams, disclosureVectors) => {
    const v = disclosureVectors[0];
    const { parties_commitment, ...rest } = publicParams;
    return { ...rest, parties: v.input_value, salt: v.salt };
  },
  // art-414-compute-rbc-action-level-private.kernel.mjs buildArtifact(raw):
  //   raw = { rbc_components: {total_adjusted_capital, authorized_control_level}, salt, insurer_type? }
  // disclosure input_value bundles insurer_type alongside the two private figures for
  // convenience -- insurer_type is already correct via the publicParams spread, so it is
  // deliberately NOT copied into the nested rbc_components object (that would change what
  // gets committed and break the self-verify below).
  "art-414-compute-rbc-action-level-private": (publicParams, disclosureVectors) => {
    const v = disclosureVectors[0];
    const { rbc_components_commitment, ...rest } = publicParams;
    const { total_adjusted_capital, authorized_control_level } = v.input_value;
    return { ...rest, rbc_components: { total_adjusted_capital, authorized_control_level }, salt: v.salt };
  },
  // art-415-check-capital-adequacy-private.kernel.mjs buildArtifact(raw):
  //   raw = { capital_inputs: {eligible_capital, risk_weighted_assets}, salt, regime?, regulatory_minimum_pct? }
  "art-415-check-capital-adequacy-private": (publicParams, disclosureVectors) => {
    const v = disclosureVectors[0];
    const { capital_inputs_commitment, ...rest } = publicParams;
    const { eligible_capital, risk_weighted_assets } = v.input_value;
    return { ...rest, capital_inputs: { eligible_capital, risk_weighted_assets }, salt: v.salt };
  },
  // art-529-ccp-default-waterfall-recompute.kernel.mjs buildArtifact(raw):
  //   raw = { waterfall_structure, loss_amount_minor_units, ccp_skin_in_game_minor_units,
  //     assessment_powers_cap_minor_units?, currency?, defaulter_im_minor_units,
  //     defaulter_default_fund_minor_units, surviving_member_default_fund_pool_minor_units, salt }
  // NOTE (2026-08-05): art-529 is not currently vendored into helm/hub/vendored/ocg/kernels
  // (a stale-pin gap, separate from this witness-sourcing gap) -- this entry is correct per
  // the kernel source but is untested against the real KERNELS registry until re-vendored.
  "art-529-ccp-default-waterfall-recompute": (publicParams, disclosureVectors) => {
    const v = disclosureVectors[0];
    const { member_figures_commitment, ...rest } = publicParams;
    const { defaulter_im_minor_units, defaulter_default_fund_minor_units, surviving_member_default_fund_pool_minor_units } = v.input_value;
    return { ...rest, defaulter_im_minor_units, defaulter_default_fund_minor_units, surviving_member_default_fund_pool_minor_units, salt: v.salt };
  },
};

export function hasWitnessAssembler(kernelId) {
  return Object.prototype.hasOwnProperty.call(ASSEMBLERS, kernelId);
}

// Sources the private raw witness for a §25 node's sampled fixture vector, then
// SELF-VERIFIES it by rebuilding the artifact through the kernel's real buildArtifact()
// and confirming every *_commitment field it derives matches what the checked-in fixture
// vector already declares. A stale or wrong disclosure witness hard-errors here -- it must
// never silently "pass" a parity check merely because a witness file exists.
export async function sourcePrivateWitness(kernelId, kernel, fixtureVector, fixturesDir) {
  const assemble = ASSEMBLERS[kernelId];
  if (!assemble) {
    throw new Error(
      `${kernelId}: no private-input witness assembler registered (OCG §25 ocg-private-input@1) — ` +
      `add one to helm/scripts/private-input-witness.mjs, reading the raw shape off this kernel's own buildArtifact() doc-comment`
    );
  }
  const disclosurePath = join(fixturesDir, `${kernelId}.disclosure.json`);
  if (!existsSync(disclosurePath)) {
    throw new Error(`${kernelId}: private_input_profile is set but no disclosure fixture exists at ${disclosurePath} — cannot source a witness`);
  }
  const disclosure = JSON.parse(readFileSync(disclosurePath, "utf8"));
  const vectors = (disclosure.vectors ?? []).filter((v) => v.name === fixtureVector.name);
  if (vectors.length === 0) {
    throw new Error(`${kernelId}: no disclosure vector named "${fixtureVector.name}" matching the sampled .fixtures.json vector`);
  }

  const raw = assemble(fixtureVector.policy_parameters, vectors);

  const rebuilt = await kernel.buildArtifact(raw, { now: null, parent_hashes: [], parent_tool_ids: [], chain_depth: 0 });
  for (const [key, declaredValue] of Object.entries(fixtureVector.policy_parameters)) {
    if (!key.endsWith("_commitment")) continue;
    const rebuiltValue = rebuilt.policy_parameters?.[key];
    if (rebuiltValue !== declaredValue) {
      throw new Error(
        `${kernelId}: disclosed witness does not reproduce the declared commitment "${key}" ` +
        `(rebuilt ${rebuiltValue}, fixture declares ${declaredValue}) — disclosure fixture is stale or wrong, refusing to source it`
      );
    }
  }

  return raw;
}
