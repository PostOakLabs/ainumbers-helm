# Helm — Operational Ownership (Phase 1)

Who maintains what, and what the shipped code guarantees regardless. Decided with
Tim 2026-07-23 (HELM-R1). These positions are revisited before Helm ships a
**write-capable connector** — that is the gate, not a date.

| Question | Position (2026-07-23) |
|---|---|
| Who patches the Local Hub on a dependency CVE? | Founder (Tim). The dependency surface is deliberately tiny (better-sqlite3, keychain lib, Node builtins — zero-npm elsewhere), which keeps the exposure small. |
| What happens to evidence and credentials if a connector version is abandoned? | **Evidence readability is not at risk:** offline verifiability is a *structural* property — the standalone Verify view checks an evidence bundle with no daemon and no connector (§5 gate #2). A vault becomes unreadable only if you lose your own keychain/OS secret, never because a connector stopped being maintained. |
| Where do security disclosures go? | **security@postoaklabs.com** (→ tim@postoaklabs.com; live, confirmed). Disclosure policy lives in `SECURITY.md` — one home, not restated here. |
| What does the credential-leak / unauthorized-action runbook look like? | See `INCIDENT-RESPONSE.md` (IR-1 credential leak, IR-2 unauthorized external action, IR-3 supply-chain). |

## Phase-1 operating envelope (consequences of the above)

- **You run the Hub.** Helm never runs a log or registry on your behalf, so there
  is no service of ours whose availability affects your workflows (D1 doctrine).
- **Read-only connectors only** for now. Current connectors are read-only
  (`google-drive.fetch`) or inbound (webhook adapter, no outbound writes) — Phase 1
  by design.
- **Updates are pull, not push** (D10 — version-check notice, no auto-updater), so a
  patch reaches a machine only when whoever runs it chooses to update: "released"
  ≠ "deployed."

## Cutting a release (v0.1.0+)

1. `node scripts/gen-release-keys.mjs` — writes public keys to `schema/release-signing-keys.json` (commit them), prints the private key blob to stdout.
2. Pipe the private key straight into the secret store — **never paste it, never write it to a file** (shell scrollback + history are a leak surface):
   ```
   node scripts/gen-release-keys.mjs | tail -n1 | gh secret set HELM_RELEASE_SIGNING_KEY_B64 --repo PostOakLabs/ainumbers-helm --body-file -
   ```
3. `git tag vX.Y.Z && git push origin vX.Y.Z` — this is the only trigger for `release.yml` (`test` → `build` → `sign-and-release`, fail-closed at each step).

**Signing status (Phase 1):** `helmd.exe` carries no Authenticode certificate, and the macOS
binaries are ad-hoc signed only (`scripts/build-sea.mjs` runs `codesign --sign -`, which is not a
Developer ID identity and is not notarized). Windows first launch therefore typically shows a
SmartScreen prompt, and macOS typically reports that the developer cannot be verified.

**Never tell a user to click past either one.** Not "Run anyway", not right-click-Open to bypass
Gatekeeper, not `xattr -d com.apple.quarantine`, not "the warning is normal, ignore it" — the last
two are what real macOS malware campaigns instruct. The download page already follows this rule;
so does this document.

What we can honestly offer instead is verification: every release publishes `SHA256SUMS`, a
DSSE-signed release manifest, SLSA build provenance, and a CycloneDX SBOM. Point users at the
checksum, and state plainly that signing is not yet in place. A user who is not willing to verify
the download should not run it.

Unsigned is a known Phase-1 gap, not a build defect, and it is tracked for Phase 2 (Azure Artifact
Signing on Windows; Developer ID + notarization + a stapled `.pkg` on macOS).

## Revisit triggers

Re-open every row above **before** any of:
1. First write-capable connector.
2. A single deployment holding credentials for more than one organization.
3. A live treasury or compliance workflow running against production data.
