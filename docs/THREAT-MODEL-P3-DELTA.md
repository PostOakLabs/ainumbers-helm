# Helm — Threat Model DELTA (Phase 3)

Adversarial review of the Phase-3 browser-first + bank-ready surfaces
(HELM-P3-R15, spec `HELM-PHASE3-BUILD-SPEC.md` §1/§2/§5). This is a DELTA over
`THREAT-MODEL.md` (Phase 1 / HELM-R1) and `THREAT-MODEL-P2-DELTA.md` (Phase 2 /
HELM-R11) — it does not restate their findings.

**Reviewed:** 2026-07-24 (6-way parallel adversarial pass: pairing/port-squat,
migration handover, browser vault, relay trust boundary, LNA/handoff+OAuth, npm
supply chain). Instrument: `node scripts/test.mjs` = **292 pass / 0 fail / 4
live-net skips** at review time.

## New assets / trust boundaries this phase

| Asset | Where | Sensitivity |
|---|---|---|
| Browser DEK (wraps connector tokens) | in-memory + `wrapped_dek` in IndexedDB (`ui/lib/vault-*`) | Critical — decrypts all browser-mode tokens |
| Passphrase-KDF fallback record | IndexedDB (`salt`+`iterations`+`wrapped_dek`) | Critical — offline-attackable oracle |
| Migration bundle (browser → daemon) | export file / loopback POST | High — carries `wrapped_dek` + `kdf` params |
| Daemon identity key (challenge proof) | `keys.mjs` Ed25519 (also signs envelopes) | Critical — the thing pairing is meant to authenticate |
| Anchor relay (`anchor.ainumbers.co`) | untrusted intermediary | Timestamp authenticity is NOT verified in-browser |

```
Hosted UI (ainumbers.co)  --[top-level nav #token= / click-gated LNA probe]-->  helmd@127.0.0.1:4173
Browser vault (OPFS/IDB, ainumbers.co origin)  --[export bundle]-->  helmd import
Browser verify  --[TimeStampReq/Resp]-->  anchor relay (UNTRUSTED)  --[RFC3161]-->  TSA
```

## Attacks attempted, defended by construction (non-findings)

- **Port refuse-start** — helmd exits (not silently re-ports) on `EADDRINUSE`
  (`server.mjs:438-445` → `index.mjs:64-68`), bind resolves before browser
  auto-open, so a squatted 4173 can't be auto-opened onto. Fixed port throughout.
- **Token scrub is synchronous, pre-network** — `readTokenFromLocation()` is the
  first statement of `boot()` (`ui/app.mjs:132`); `history.replaceState` runs
  before `saveToken` / `/pair/redeem` (`ui/api.mjs:34-39`). Token lives in the URL
  **fragment** — never sent in `Referer` or to the server.
- **Pairing-nonce single-use + TTL** — delete-then-verify, server-clock TTL
  (`token.mjs:53-58`); constant-time bearer compare (`timingSafeEqual`,
  `token.mjs:31-37`).
- **Token scope containment** — hosted origin reaches only `/version` +
  `/pair/challenge` (token-free, non-sensitive); vault/journal/run behind
  Host+Origin+Bearer (`server.mjs:369-414`). Daemon bearer cannot unlock
  browser-origin OPFS/PRF (separate trust domain).
- **Browser vault crypto core** — PRF wraps a CSPRNG-random DEK, HKDF-SHA256
  derivation; AES-GCM with fresh 12-byte IV per seal, tag verified on every open;
  PBKDF2-HMAC-SHA256 @ 600k, unique 16-byte salt; DEK never persisted plaintext
  or logged; journal is NOT PRF-wrapped (lost key ⇒ reconnect tokens only, journal
  readable) — `ui/lib/vault-crypto.mjs`, tests green.
- **No forced PRF→passphrase downgrade** — `unlockRecord` dispatches strictly by
  the record's own `wrap_method`; `prf.enabled` checked AND a real test assertion
  performed at enrollment (`vault.mjs:78-94`).
- **Migration import fails closed** — schema-validated (`additionalProperties:
  false`, sha256 patterns) before any digest work; fresh-reauth gate checked before
  reading entries; no partial writes on bad bundle; JSON-only (no zip-slip);
  `source_origin` regex-constrained + base64url-encoded before touching FS;
  post-import chain re-verified (`migration-import.mjs`).
- **Relay anti-substitution** — the browser verifies the returned TST's
  `messageImprint` against the checkpoint's **own** DSSE-signed, independently
  recomputed `journal_root_digest` — NOT the relay-returned `anchored_hash`
  (`verify-bundle.mjs:37-55`). Hash-alg downgrade rejected: imprint OID must equal
  SHA-256 (`der.mjs:113`). A relay swapping a valid TST for a different document →
  `bound:false`.
- **Supply-chain crypto core** — OIDC trusted publishing (no `NPM_TOKEN` in repo);
  release signing key only from CI secret, only public halves committed; dual-sign
  Ed25519 + ML-DSA-44; fail-closed verify before publish; tag-only + manual-approval
  release; npm postinstall re-verifies binary sha256. ZERO-DEP root ⇒ no lockfile
  needed.
- **LNA/handoff fails closed** — `probeDaemon` fires nowhere in production (not on
  page load); every LNA/PNA failure folds to clean browser mode; PKCE S256 +
  128-bit `state` + fragment-free loopback callback; version negotiation degrades
  (never hard-fails / never lets a daemon over-claim into an unsafe state).

## Findings (residual risk — filed as follow-on WUs)

Severity: CRIT ship-blocker · HIGH fix-before-migration-UI · MED fix-this-phase ·
LOW/INFO hardening.

### R15-F1 · CRIT · Signed-challenge daemon proof has no key pinning
`hub/challenge.mjs:20` `verifyChallenge` checks the signature against the
**publicKey the responder itself supplied** — self-consistency, not identity. A
port squatter mints its own Ed25519 keypair, signs its own nonce, returns a
consistent `{nonce, signature, publicKey}` triple, and passes. Nothing compares
`publicKey` to the daemon's real `keys.mjs` identity obtained out-of-band, and the
pairing link (`token.mjs:28`) carries no identity fingerprint — so no pinning
material exists anywhere. The `challenge.test.mjs:16` "different keypair fails"
case swaps only the pubkey (keeping the old signature) and thus fails for the wrong
reason; the true squat triple is uncovered. **Effect:** the control at the heart of
"daemon proves itself before migration" provides zero anti-impersonation value.
**Fix:** deliver the daemon identity-key fingerprint through a trusted channel
(embed `&fp=` in the `#token=` link only real helmd can mint), require
`verifyChallenge(...) && fingerprint === pinned`. → **HELM-P3-SEC-1**.

### R15-F2 · HIGH · Daemon-proof + fresh-reauth ordering is unenforced (unwired)
`verifyChallenge` has **zero production callers** (grep). `submitMigrationToDaemon`
(`ui/lib/migration.mjs:81`) gates only on `freshReauth === true` — a client-set
boolean — and the daemon import trusts `fresh_reauth === true` symmetrically. The
P3-D9 "prove, THEN fresh WebAuthn, THEN send" sequence is prose in comments with no
structural enforcement. Mitigated today only because the migration UI (P3-U2..U4
callers) isn't built, so the send path can't yet run against a live squatter.
**Fix:** make `submitMigrationToDaemon` require a verified+pinned challenge object
as a parameter (not a bare boolean); add a wired test exercising the full order. →
**HELM-P3-SEC-1** (with F1).

### R15-F3 · HIGH · `SHA256SUMS` documented but never generated
`docs/CATEGORIZATION-SUBMISSIONS-RUNBOOK.md:82-83` tells the operator to use
`SHA256SUMS` "already produced by the release pipeline (P3-D1 free hardening)" —
but `release.yml` emits no such file (grep: only doc references). The AV clean-file
submission workflow dead-ends. Per-artifact sha256 does exist inside the signed
`release-manifest.json`. **Fix:** add a `sha256sum * > SHA256SUMS` step to
`sign-and-release` and upload it (or correct the runbook to read from the manifest).
→ **HELM-P3-SEC-2**.

### R15-F4 · HIGH · `attest-build-provenance` documented but not wired
Spec D-SIGN-1 free hardening called for `actions/attest-build-provenance` in
`release.yml`; it is absent. The npm OIDC provenance path is disabled by default
(deferred). So the release's entire root of trust is the self-signed,
committed-public-key manifest — a TOFU model with no external witness (Sigstore /
Rekor). This is the one control the committed-key manifest genuinely cannot provide.
**Fix:** add `permissions: attestations: write, id-token: write` + an
`attest-build-provenance` step over `dist/upload/*`. → **HELM-P3-SEC-2**.

### R15-F5 · MED · Relay offline queued/skipped-marker path is unimplemented
`schema/anchor_queue_marker.schema.json` + fixtures exist, but no producer emits a
marker on relay failure and no verifier branch renders one (grep: zero non-schema
hits). `anchor-client.mjs` `anchorRfc3161`/`anchorOpenTimestamps` **throw** on
`!res.ok`/timeout/bad content-type and have no orchestrating caller. So the P3-D4
guarantee — "all egress blocked ⇒ still produce a valid checkpoint with a queued
marker, tool 100% functional" — is **not demonstrably wired**; §5 exit gate #1
(relay-blocked works) is UNMET as shipped. **Fix:** implement the anchor caller with
a `try/catch` distinguishing egress-blocked/unreachable/relay-error, write a
schema-valid marker in place of `anchors[]`, never let a relay failure abort
checkpoint creation; add the verifier's neutral "queued/skipped" render branch. →
**HELM-P3-SEC-3**.

### R15-F6 · MED · Daemon-mediated migration POST is non-functional
`submitMigrationToDaemon` (`ui/lib/migration.mjs:88`) sends `{bundle,
fresh_reauth}` with **no `raw_entries`**; the daemon route requires
`Array.isArray(body.raw_entries)` → `400 missing_bundle_or_raw_entries`
(`server.mjs:337`). The loopback migration transport can never succeed (only the
export-file path works). Fails closed (safe) but is a real break the mock-only test
missed. **Fix:** include `raw_entries` in the POST body. → **HELM-P3-SEC-3**.

### R15-F7 · MED · `drive.readonly` never migrated to `drive.file`
`hub/connectors/google-drive-fetch.contract.json:7` still declares
`["drive.readonly"]`; the module is hardcoded on it (`:4,54`) and the scope
propagates into signed `connector_attestation` fixtures. `drive.file` appears
nowhere in the repo. P3-D5 explicitly required migrating the daemon connector (and
never copying readonly to the browser). `drive.readonly` is a CASA-restricted scope
($500–4.5k/yr assessment) — dead at $0 budget. **Fix:** migrate contract+module to
`drive.file` + Picker; regenerate golden attestation fixtures. → **HELM-P3-SEC-4**.

### R15-F8 · MED · Silent overwrite of daemon vault state on re-import
`importMigrationBundle` (`hub/migration-import.mjs:94-95`) writes
`migrated-vault:${source_origin}` via unconditional `vaultSet` — no existence
check. `source_origin` is attacker-controlled bundle content; a second/crafted
import silently overwrites prior wrapped-DEK material (§5 forbids overwrite without
confirmation); markers accumulate with no idempotency guard. **Fix:** refuse (or
require explicit `overwrite:true`) when a vault ref for that origin exists; make the
marker append idempotent on `(source_origin, journal_root_digest)`. →
**HELM-P3-SEC-3** (with F6).

### R15-F9 · MED · Browser passphrase vault has no strength enforcement
`enrollPassphrase` (`ui/lib/vault.mjs:136`) accepts any string. The IndexedDB record
(`wrapped_dek`+`salt`+`iterations`) is a complete offline oracle to any origin XSS
or local disk read; 600k PBKDF2 iterations don't save a 6–8 char passphrase.
**Fix:** enforce a length + entropy floor at enrollment before deriving. →
**HELM-P3-SEC-4** (with F7).

### R15-F10 · LOW · Overconfident TST-time badge under a hostile relay
The browser verifies binding but performs **zero** TSA signature/chain
verification offline (`der.mjs` header). A hostile relay knows the client's digest
(just POSTed) and can fabricate a TSTInfo with that imprint + an arbitrary
`genTime`; `verify.mjs:66` renders a green "✓ … TSA time \<forged\>" badge, visually
separated from the honest "✗ NOT checked: chain of trust" fence. **Fix:** render
`genTime` with an inline "signature not verified offline" qualifier or a
non-success badge color. → **HELM-P3-SEC-5** (presentation batch).

### R15-F11 · LOW · No post-anchor imprint check (defense-in-depth)
`anchor-client.mjs:48-56` stores whatever DER the relay returns without asserting
`messageImprint == submitted hash` at anchor time; a hostile/garbage token is only
caught later at verify (and never for signature). **Fix:** run
`parseRfc3161MessageImprint` and assert equality immediately, feeding F5's
relay-error marker path. → **HELM-P3-SEC-5**.

### R15-F12 · LOW · Token `ref` not bound as AES-GCM AAD (vault blob-swap)
`encryptWithDek`/`decryptWithDek` (`ui/lib/vault-crypto.mjs:109,113`) pass no
`additionalData`; all tokens share one DEK, so an IndexedDB-writer can move the
`ms-graph` blob into the `github` slot and it decrypts cleanly. **Fix:** pass `ref`
(+ store-version) as AAD both sides. → **HELM-P3-SEC-5**.

### R15-F13 · LOW · `release_url` scheme unrestricted; probe timeout fallback
(a) `schema/version_notice.schema.json:13` `release_url` is `format:uri` with no
scheme allow-list — latent `javascript:` XSS the day a UI renders it as `<a href>`;
constrain to `^https://`. (b) `handoff.mjs:56` drops its timeout when
`AbortSignal.timeout` is absent; use an `AbortController` fallback. →
**HELM-P3-SEC-5**.

### R15-F14 · INFO · Vault-record KDF metadata unauthenticated; raw DEK retained
`kdf.iterations`/`salt`/`wrap_method` not AEAD-covered — a record-writer can set
`iterations:1` (DoS the legit unlock only, not an attacker win); and
`VaultTokenStore` retains raw DEK bytes indefinitely, defeating the non-extractable
import. Both inherent to browser-local design; note + accept, or bind KDF metadata
as AAD / floor iterations at read. → tracked with **HELM-P3-SEC-5**.

## Residual risk statement (Phase 3)

The Phase-3 cryptographic cores — browser vault AEAD, relay anti-substitution,
release dual-sign, PKCE/LNA fail-closed — are correctly built and test-green. The
**ship-blocker is R15-F1 (+F2)**: the pairing "daemon proves itself" control is both
unpinned and unwired, so it authenticates nothing. **The migration UI (P3-U2..U4)
MUST NOT ship until F1/F2 land** — until then the browser→daemon handover has no
cryptographic proof of who it is handing to.

§5 exit-gate status at review: gates that are unit-provable pass (two-tab safety,
vault fallback, skew degrade, bundle portability, digest chain). **Gate #1
(daemon-less completeness with relay blocked) is UNMET** — the queued-marker offline
path is schema-only, unwired (R15-F5). **Gate #4/#5 (handoff/migration) rest on the
unpinned proof (R15-F1)** and are not securely met. Supply-chain "free hardening"
(gate #8) is partially unmet (R15-F3/F4 documented-not-wired).
