# Helm — Incident Response Runbook (Phase 1)

**Scope:** failure modes that do not exist elsewhere in the AINumbers.co product line
because Helm is a credential-holding daemon: **credential leak** and **unauthorized
external action**. Written 2026-07-23 (HELM-R1).

**Disclosure contact:** security@postoaklabs.com (routes to tim@postoaklabs.com; live,
also published in `SECURITY.md`). Acknowledge within 5 business days.

**Phase-1 responder reality (per brief §10, decided with Tim 2026-07-23):**
founder-only, best-effort, no uptime/response SLA, no external customers yet. This
runbook is the *procedure*; it does not imply 24/7 coverage.

---

## Severity

| Sev | Definition | Example |
|---|---|---|
| SEV-1 | Live credential exposed, or an unauthorized external write occurred | Vault token in a log shipped off-box; connector wrote to a real API without consent |
| SEV-2 | Credential *could* have leaked but no confirmed exposure; egress bypass with no proven exfiltration | F1 redirect bypass observed in the wild; state dir world-readable on a customer box |
| SEV-3 | Integrity/verification defect, no credential impact | Journal replay mismatch; release manifest verify anomaly |

---

## IR-1 — Credential leak (vault token exposed)

**Detect:** token found in a log/export (grep-gate regression), a provider reports
anomalous token use, or F2/F5-class exposure is confirmed on a real deployment.

**Contain (do first, in order):**
1. **Revoke at the provider.** Use the connection's revocation endpoint —
   `POST /vault/connections/{id}/revoke` calls it and deletes the local vault ref
   (`revokeConnection`, `oauth-pkce.mjs`). If the daemon is unreachable, revoke
   directly in the provider's console (Google: Security → Third-party access).
2. **Rotate the pairing token.** Delete `state/token`; restart helmd; re-pair the UI
   from the freshly printed `#token=` URL. Any previously-issued token is now dead.
3. **Rotate any release signing key** only if the leak path could reach CI secrets
   (it should not — keys live only in `HELM_RELEASE_SIGNING_KEY_B64`).

**Eradicate:** identify the leak channel (log line, export, process-listing per F2,
adjacent key-file read per F5), patch it, add a regression test/grep-gate so the same
channel fails CI.

**Recover:** re-issue connections via the normal OAuth PKCE consent flow (new tokens,
smallest scope). Verify no lingering vault refs: `vault-index.json` and
`connections.json` should agree and hold no orphaned refs.

**Evidence:** the journal is append-only and running-hash-chained — do **not** rewrite
it. Capture the affected `state/` dir (excluding live secrets) for the postmortem.

## IR-2 — Unauthorized external action (egress bypass / rogue connector)

**Detect:** egress transcript shows a `decision: "allowed"` to an unexpected host, or a
provider shows a call Helm should not have made (F1 redirect-follow is the known path).

**Contain:**
1. **Stop the daemon** (`helmd` process) to halt further calls.
2. **Revoke the connection(s)** used by the offending connector (IR-1 step 1).
3. Quarantine the connector contract — the run engine loads signed contracts; remove
   or disable the contract file so it cannot be re-selected.

**Eradicate:** patch the egress choke point (F1: `redirect: "manual"` +
per-hop re-validation in `performEgress`). Confirm `connector.test.mjs` covers the new
redirect-bypass negative case.

**Recover:** re-enable the connector only after the fix ships and the negative test is
green. Re-run affected workflows in **dry-run** first.

**Scope the blast radius from evidence:** the egress journal stream
(`egress:<connectorId>`) records every boundary crossing with request/response digests
— reconstruct exactly what was sent and to which host. This is why blocked calls are
journaled, not swallowed.

## IR-3 — Supply-chain / release compromise

**Detect:** `verify-release-manifest.mjs` fails, a vendored-file hash mismatch (once
`HELM-SEC-3` gate lands), or a published binary's DSSE envelope fails dual-sig verify.

**Contain:** pull the affected GitHub release (it ships as a **pre-release**, limiting
exposure); post the bad version + expected DSSE digest to the disclosure channel.

**Eradicate:** re-vendor from the correct pinned SHA (`scripts/vendor.mjs`,
single-writer); re-cut the release from a clean tag; rotate signing keys if key
compromise is suspected.

**Recover:** publish a new signed release; users on the version-check notice see the
update (no auto-updater in Phase 1 — D10).

---

## Standing procedures

- **Do not delete the journal** during any incident — it is the evidence of record.
- **Backups:** `hub/backup.mjs` produces an encrypted archive; restore is tested
  (`backup.test.mjs`). Keep a pre-incident backup before mutating state.
- **Dependency CVEs:** best-effort patch cadence (no SLA, per brief §10); triage via
  the disclosure contact. Dependency surface is intentionally tiny (better-sqlite3,
  keychain lib, Node builtins — zero-npm elsewhere).
- **Postmortem:** blameless, written for every SEV-1/SEV-2; include timeline, blast
  radius from the journal, root cause, and the regression gate added.
