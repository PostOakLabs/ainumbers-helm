# Helm — Threat Model (Phase 1)

**Scope:** `hub/` (helmd daemon), `ui/` (helm.html), `schema/`, `scripts/` (vendoring + release).
**Reviewed:** 2026-07-23 (HELM-R1, adversarial pass over H1/H5/H6/H8 surfaces).
**Status:** Phase 1 foundation. No external customers yet; no write-capable connector shipped.

Helm is the deliberate opposite of the rest of AINumbers.co: a locally-installed
daemon that holds live OAuth tokens, calls private APIs, and keeps a durable signed
journal. It is a different liability class than a static HTML tool and is reviewed as
such. This document records the trust boundaries, the adversaries, what the design
already defends, and the residual risks accepted for Phase 1.

---

## 1. Assets

| Asset | Where | Sensitivity |
|---|---|---|
| OAuth access/refresh tokens | OS keychain / DPAPI / encrypted-file fallback (`vault.mjs`) | Critical — live credentials to customer systems |
| Loopback pairing bearer token | `state/token`, mode-0600 | High — grants full daemon API access |
| Release signing keys (Ed25519 + ML-DSA-44) | CI secret `HELM_RELEASE_SIGNING_KEY_B64`, never in repo | Critical — forges trusted binaries |
| Journal / checkpoints / evidence bundles | SQLite + exports | High integrity, low confidentiality (secrets/raw payloads redacted by default) |
| Vendored OCG kernels + verify libs | `hub/vendored/ocg/` (pinned SHA) | High integrity — kernel-parity + proof trust root |

## 2. Trust boundaries

```
Browser UI (helm.html)  --[127.0.0.1 REST+SSE, Host+Origin+Bearer]-->  helmd
System browser (OAuth)  --[ephemeral loopback listener, state+path-token]-->  helmd
helmd  --[default-deny egress allowlist]-->  external APIs / webhooks
CI (tag build)  --[dual-signed DSSE release manifest]-->  end users
site repo @ pinned SHA  --[vendor.mjs single-writer]-->  hub/vendored/ocg/
```

## 3. Adversaries

- **A1 — Malicious local web page** in the user's browser attempting to reach the daemon (DNS-rebinding, CSRF, cross-origin fetch).
- **A2 — Local unprivileged process** on the same machine (process-listing snoop, reading state dir, racing the loopback).
- **A3 — Malicious/compromised connector or workflow manifest** trying to exfiltrate data past the egress allowlist or steal vault secrets.
- **A4 — Supply-chain attacker** tampering vendored kernels or the release pipeline.
- **A5 — Network attacker** between helmd and an OAuth/token endpoint.

## 4. Defenses in place (verified by test, HELM-R1)

| Surface | Defense | Instrument |
|---|---|---|
| Loopback (A1) | Exact `Host` = `127.0.0.1:<port>` (rebind defense), exact `Origin` match (no wildcard CORS), Bearer token on every call, no side effects on GET | `hub/server.test.mjs` 7/7 |
| Pairing token | 256-bit random, mode-0600 file, constant-time compare (`timingSafeEqual`) | `hub/token.mjs`, server tests |
| OAuth (A5 partial) | RFC 8252 loopback PKCE (S256), 128-bit `state`, 64-bit unguessable callback path, 5-min flow TTL, ephemeral single-shot listener isolated from the main API | `hub/oauth-pkce.mjs` |
| Secret discipline (A2/A3) | Tokens only in vault; config/journal/registry hold opaque refs; connector sees only its scoped vault slice; grep-gate proves token never in exports/logs | `hub/vault-secret-gate.test.mjs` 1/1 |
| Egress (A3) | Default-deny per-connector (host, method) allowlist; every decision (allow/block) journaled; blocked call throws, never returns a fake response | `hub/connector.test.mjs` 5/5 |
| Journal integrity (A4) | Append-only per-stream running hash; tampered entry breaks the chain and is detected on replay | `hub/journal.test.mjs` 7/7, `round-trip.test.mjs` 2/2 |
| Release trust (A4) | Dual-sign Ed25519 (MUST) + ML-DSA-44 (SHOULD) DSSE; `verify-release-manifest.mjs` fail-closed before publish; keys never in repo | `hub/envelope.test.mjs` 7/7 |
| Vendoring (A4) | Fetch by immutable pinned SHA (git verifies object hashes); single-writer; MANIFEST.json of per-file sha256 | `scripts/vendor.mjs` |

## 5. Findings (HELM-R1 adversarial pass)

All findings filed as follow-on board rows (`board/queued/HELM-SEC-*`). Severity is
this reviewer's judgment for the Phase-1 posture (no external customers, no write
connector). None block Phase-1 exit; F1/F2 SHOULD land before the first real connector.

### F1 — Egress allowlist bypass via HTTP redirect (High)
`performEgress` (`hub/connector.mjs`) calls `fetch(url)` with Node's default
`redirect: "follow"`. The allowlist is checked only against the **initial** URL's
host. An allowed host that returns a 3xx to a disallowed host causes fetch to follow
the redirect and egress to the unapproved host, while the transcript records only the
original (allowed) host. This defeats §5 gate #3 for a redirecting endpoint.
**Fix:** set `redirect: "manual"` and re-validate the `Location` host+method against
the contract allowlist on each hop (or reject redirects outright). → `HELM-SEC-1`.

### F2 — Windows DPAPI secret passed on the PowerShell command line (High)
`vault.mjs` `windowsSet`/`windowsGet` interpolate the base64 plaintext (set) and
ciphertext (get) into a `powershell.exe -Command` string. The base64 **plaintext** is
trivially decoded and is visible in the process command line (`Get-CimInstance
Win32_Process | select CommandLine`) to any process for the lifetime of the call, and
is captured by PowerShell ScriptBlock logging / transcription (Event 4104) where
enabled. Charset is base64 so command injection is not possible, but confidentiality
is lost. **Fix:** pass the secret via stdin (`spawnSync` `input:`) read through
`[Console]::In.ReadToEnd()`, or a mode-0600 temp file deleted after use. → `HELM-SEC-2`.

### F3 — No vendored-code integrity gate; single-writer rule is prose-only (Medium)
`ci.yml` never re-verifies `hub/vendored/ocg/` against `MANIFEST.json` or the upstream
pinned SHA. A PR can edit vendored kernel/verify bytes (and regenerate MANIFEST to
match) and merge green, defeating the "kernels never edited in helm; fix upstream +
re-vendor" rule and the D3 byte-for-byte kernel-parity guarantee. The rule is doctrine,
not enforcement. **Fix:** CI step that re-hashes vendored files vs MANIFEST and
re-fetches `pinnedSha` to confirm bytes match upstream; fail on drift. → `HELM-SEC-3`.

### F4 — OAuth endpoint scheme not validated (Medium)
`handleBeginConnection` (`server.mjs`) + `startFlow`/`exchangeCode`
(`oauth-pkce.mjs`) accept arbitrary `authorizationEndpoint`/`tokenEndpoint` with no
`https://` requirement. A misconfigured or hostile manifest with an `http://`
tokenEndpoint sends the authorization code **and** the PKCE `code_verifier` in
cleartext (A5). **Fix:** require `https:` for both endpoints; allow `http:` only for a
`127.0.0.1` loopback mock in tests. → `HELM-SEC-4`.

### F5 — File-fallback vault key stored adjacent to ciphertext (Low, accepted)
The AES-256-GCM fallback tier derives its key from `state/vault-fallback.key`
(auto-generated, mode-0600) sitting in the **same** state directory as the ciphertext
blobs. Anyone who can read the vault dir reads both key and ciphertext, so the
"encrypted fallback" adds essentially no at-rest protection against a local file read
(A2) — it only protects a ciphertext-only copy/backup. **Accepted for Phase 1**;
the native keychain/DPAPI tier is the real protection and the fallback exists for
headless/CI. Documented so no false confidence is implied. Revisit: derive the
fallback key from a user passphrase or OS-bound secret. → tracked in `HELM-SEC-5`.

### F6 — PQC co-signature strip downgrades silently to Ed25519-only (Low, accepted)
`verifyEnvelope` treats a **missing** ML-DSA-44 signature as valid
(`valid = ed25519 === true && mldsa44 !== false`). Per D5, ML-DSA-44 is SHOULD and
Ed25519 is MUST, so stripping the PQC signature still verifies. **Accepted** — this is
the documented SHOULD/MUST split; a *present-and-wrong* PQC sig is still caught. Note
for the day PQC becomes mandatory: flip to require both. → tracked in `HELM-SEC-5`.

### Hardening notes (non-findings, batched into `HELM-SEC-5`)
- No timeouts on `fetch` in `exchangeCode`, `performEgress`, `revokeConnection` — a
  slow/hung endpoint stalls the flow. Add per-call timeouts.
- SSE `/events` accepts unbounded concurrent connections — a local process could
  exhaust handles. Cap connections.
- macOS/Linux keychain CLIs (`security add-generic-password -w`, `secret-tool store`)
  receive the secret via argv/stdin respectively; `-w` argv exposure is same-user only
  and lower severity than F2 but worth moving to stdin for parity.

## 6. Residual risk statement (Phase 1)

With F1 and F2 open, Helm should **not** ship a write-capable connector or handle a
second customer's credentials (per brief §10 gate). The offline verifiability of
evidence bundles is a **structural** property — the standalone Verify view checks a
bundle with no daemon and no connector (§5 gate #2, `bundle.test.mjs` 6/6) — so a
connector going unmaintained never renders a customer's evidence unreadable, even
under the best-effort support posture (see `OPERATIONS.md`).
