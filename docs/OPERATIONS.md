# Helm — Operational Ownership (Phase 1)

Answers to the brief's §10 operational-ownership questions, **decided with Tim
2026-07-23** (HELM-R1). These are the Phase-1 positions; each is honest about a
pre-revenue, founder-run, no-external-customer stage. They must be revisited before
Helm ships a **write-capable connector** or handles a **second customer's
credentials** — that is the gate, not a date.

| §10 question | Decision (2026-07-23) |
|---|---|
| Who patches the Local Hub on a dependency CVE, and target time-to-patch? | Founder (Tim). **Best-effort, no SLA.** Patches ship as capacity allows. Honest for pre-revenue; the dependency surface is deliberately tiny (better-sqlite3, keychain lib, Node builtins — zero-npm elsewhere), which keeps the exposure small. Revisit to a real SLA before the first paying customer. |
| Who is on call if a connector breaks mid-workflow? | **Deferred — no external customers yet.** On-call is undefined until the first customer runs a live connector. Write-capable connectors are gated behind making this decision. |
| What happens to a customer's evidence/credentials if a connector version is abandoned? | **Best-effort connector support** (no migration/deprecation commitment yet). **But evidence readability is not at risk:** offline verifiability is a *structural* property — the standalone Verify view checks an evidence bundle with no daemon and no connector (§5 gate #2). A vault becomes unreadable only if the customer loses their own keychain/OS secret, not because Helm stops maintaining a connector. |
| Where do security disclosures go? | **security@postoaklabs.com** (→ tim@postoaklabs.com; live, confirmed). Published in `SECURITY.md`. Acknowledge within 5 business days. |
| What does the credential-leak / unauthorized-action runbook look like? | See `INCIDENT-RESPONSE.md` (IR-1 credential leak, IR-2 unauthorized external action, IR-3 supply-chain). |

## Phase-1 operating envelope (consequences of the above)

- **No uptime or response SLA.** Helm is customer-installed infra; the customer
  operates it (D1 doctrine). Helm never runs a log/registry on the customer's behalf.
- **No write connector, no multi-customer credentials** until on-call + patch-SLA are
  decided. Current connectors are read-only (`google-drive.fetch`) or inbound
  (webhook adapter, no outbound writes) — Phase 1 by design.
- **Updates are pull, not push** (D10 — version-check notice, no auto-updater), so a
  patch reaches customers only when they choose to update. Factor this into any future
  time-to-patch SLA: "released" ≠ "deployed."

## Cutting a release (v0.1.0+)

1. `node scripts/gen-release-keys.mjs` — writes public keys to `schema/release-signing-keys.json` (commit them), prints the private key blob to stdout.
2. Pipe the private key straight into the secret store — **never paste it, never write it to a file** (shell scrollback + history are a leak surface):
   ```
   node scripts/gen-release-keys.mjs | tail -n1 | gh secret set HELM_RELEASE_SIGNING_KEY_B64 --repo PostOakLabs/ainumbers-helm --body-file -
   ```
3. `git tag vX.Y.Z && git push origin vX.Y.Z` — this is the only trigger for `release.yml` (`test` → `build` → `sign-and-release`, fail-closed at each step).

**Windows note:** `helmd.exe` is unsigned (no Authenticode certificate in Phase 1) — first launch shows a SmartScreen "Windows protected your PC" prompt. Users click "More info" → "Run anyway". This is expected until Phase 2 code-signing is budgeted; it is not a build defect.

## Revisit triggers

Re-open every row above **before** any of:
1. First write-capable connector.
2. Second customer's credentials on any single deployment’s support scope.
3. First paying customer running a live treasury/compliance workflow.
