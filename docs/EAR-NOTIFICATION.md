# Export classification — EAR self-classification one-pager

**Status:** self-classification working note, not a BIS ruling. Review with
counsel before relying on it for an actual export decision; this exists so
the classification and the one-time notification requirement are documented
in one place instead of tribal knowledge.

## What Helm ships that touches crypto controls

`ainumbers-helm` (this repo) contains publicly available, open-source
(Apache-2.0) source code implementing:

- symmetric/asymmetric encryption for local secret storage (OS-keychain /
  DPAPI-backed vault, `hub/vault.mjs`, `ui/lib/vault-crypto.mjs`)
- digital signatures over evidence bundles — Ed25519 (MUST) and ML-DSA-44
  (SHOULD, a post-quantum signature scheme), `hub/envelope.mjs`,
  `hub/release-keys.mjs`
- RFC 3161 timestamp-token parsing/verification (`ui/vendored/der.mjs`,
  `hub/vendored/anchor-suite/`)

This is the kind of functionality classified under **ECCN 5D002** ("Category
5, Part 2" — information security) in the Commerce Control List, because it
implements or uses cryptography beyond the mass-market carve-outs.

## Why this repo is exempt from EAR licensing

Under **15 CFR § 742.15(b)** (License Exception ENC's "publicly available"
provision, alongside the parallel §734.3(b)(3) carve-out for publicly
available encryption source code and the object code compiled from it):

- the source code is **published** (public GitHub repo,
  `github.com/PostOakLabs/ainumbers-helm`, Apache-2.0 — anyone can read,
  download, and compile it, with no access restriction);
- it is not subject to an express agreement for the payment of licensing
  fees or royalties for commercial production or sale of any product
  developed with the source code; and
- **BIS and the ENC Encryption Request Coordinator must be notified by
  email, once, of the Internet location (URL) of the publicly available
  source code**, at or before the time it is made publicly available.

Meeting these conditions means the source code (and object code compiled
from it) is **not subject to the EAR** — no export license is required to
publish it, and no ongoing self-classification report (5D002 "self
classification" filings under §742.15(b)(1)) is owed, because publicly
available crypto source code is outside license-exception territory
entirely, not merely under a license exception. The one-time notification
below is the only administrative step this exemption requires.

## Notification already due

The repo went public **2026-07-24** (per `HELM-PHASE4-BUILD-SPEC.md` §1 /
Tim's Apache-2.0 decision). The notification email should be sent as close
to that date as practicable — see the drafted email in
`docs/EAR-NOTIFICATION-EMAIL-DRAFT.md`. **Tim sends this email himself** (not
an automated or agent-sent notification) — record the actual send date here
once it goes out.

| Field | Value |
|---|---|
| Repo made public | 2026-07-24 |
| Notification email drafted | 2026-07-24 (this WU, HELM-P4-C1) |
| Notification email sent | _(fill in when Tim sends it)_ |
| Recipients | crypt@bis.doc.gov; enc@nsa.gov |
| URL notified | https://github.com/PostOakLabs/ainumbers-helm |

## If this ever changes

Re-run this classification if the repo starts shipping a **compiled
binary distribution channel that is not itself publicly available in
source form** (e.g. a closed-source SEA binary sold without the
corresponding source), or if crypto scope expands meaningfully (e.g. adding
a new controlled primitive). The source-availability condition, not the
binary, is what carries the exemption.
