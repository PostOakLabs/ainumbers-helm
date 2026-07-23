# Helm — Threat Model DELTA (Phase 2)

Adversarial review of the Phase-2 self-integration + compile surfaces
(HELM-P2-R11, spec `HELM-PHASE2-BUILD-SPEC.md` §2/§6/§10). This is a DELTA over
`THREAT-MODEL.md` (Phase 1 / HELM-R1) — it does not restate Phase-1 findings.

## Scope reviewed

- **P2-H9a** — guarded egress client (`hub/connector.mjs` `performEgress`,
  resolved-IP deny list, DNS-rebinding guard, manual-redirect re-check) +
  credential-provider (`hub/credential-provider.mjs`) around the shipped vault.
- **P2-H9b** — connectors MVP: `http-send.mjs`, `smtp-send.mjs`, OAuth
  loopback+PKCE (`oauth-pkce.mjs` / `oauth-providers.mjs` / `server.mjs`
  `/vault/connections/begin`).
- **P2-C1** — pack compiler (`scripts/compile-packs.mjs`): can a compiled pack
  smuggle I/O?

## Attacks attempted, defended by construction (non-findings)

- **Egress default-deny** — a connector reaches only `(host, method)` pairs in
  its own contract allowlist; no wildcard, no fallthrough (`assertEgressAllowed`).
  Verified: `connector.test.mjs`, `http-send.test.mjs`, `smtp-send.test.mjs`.
- **Redirect-target bypass (Phase-1 F1)** — `redirect:"manual"`; every hop
  (incl. redirect Location) re-runs allowlist + resolved-IP check + journal.
- **IP-literal SSRF / metadata address** — `169.254.169.254`, `127/8`, RFC-1918,
  CGNAT, IPv6 loopback/ULA/link-local, and `::ffff:` v4-mapped literals all
  denied (`isDeniedIp`); an unparseable literal is refused, not guessed.
- **Secret-ref leakage into log/export** — egress journal records only
  `headerNames.sort()` and request/response **digests**, never header values or
  bodies; vault stores ciphertext + opaque ref; token values never written to
  config/connections.json/logs. Verified: `vault-secret-gate.test.mjs` (test:
  "secret never appears in plaintext anywhere under HELM_HOME").
- **OAuth flow integrity** — S256 PKCE, `state` check, ephemeral 127.0.0.1
  single-shot listener, Host validation, unguessable per-flow path token,
  5-min TTL, `isSecureEndpoint` (https, loopback-exempt) enforced at
  `server.mjs:78` before `startFlow`. Loopback deny-list exemption is
  **structural** (OAuth listener + daemon API call `http`/`fetch` directly, never
  through `performEgress`) — not a carve-out an operator can widen.
- **Compiled pack I/O smuggle (C1)** — see verdict below.

## Findings

### P2-F1 — DNS-rebinding TOCTOU between the resolved-IP check and the connect (Medium)

`assertResolvedIpAllowed(host)` resolves the hostname and checks the resulting
IPs against the private/metadata deny list, then `fetch(url)` (connector.mjs:227)
and `openSocket(host, …)` (smtp-send.mjs:220) perform their **own, independent**
DNS resolution to actually connect. The IP that was checked is not guaranteed to
be the IP connected to. An attacker who controls DNS for a host the operator has
**already allowlisted** can answer the guard's lookup with a public IP and the
connect's lookup with `169.254.169.254` / an RFC-1918 host (short-TTL rebinding),
defeating the private-range deny at connect time.

Constrained (requires attacker-controlled DNS for an explicitly allowlisted
host), so Medium not High — but it is the core SSRF guard's weakest seam and it
affects **both** the HTTP and SMTP egress paths.

Fix direction: resolve once, pin the vetted IP, and connect to the IP literal
(HTTP: custom `dispatcher`/lookup that reuses the checked address; SMTP: connect
to the resolved IP with `servername: host` for TLS). Filed: **HELM-P2-R11-F1**.

### P2-F2 — SMTP STARTTLS upgrade validates the cert against the wrong name (Medium)

`smtp-send.mjs` runs the dialogue with `heloHost: "helm.local"` (line 221) and
then upgrades STARTTLS with `upgradeToTls(activeSocket, heloHost)` (line 133),
so the TLS **servername** (SNI + cert-hostname check) is `"helm.local"` — the
client's EHLO identity — instead of the actual relay `host`. The AUTH LOGIN
username/password ride exactly this channel. The implicit-TLS path
(`defaultOpenSocket`, `servername: host`) is correct; only the STARTTLS upgrade
is wrong. Against a real relay this fails closed (cert mismatch → handshake
error, `rejectUnauthorized` default true), so it is a correctness+security
defect rather than a silent downgrade — but the cert is not being validated
against the host being trusted. Untested today: the connector test overrides the
socket, so the real TLS upgrade is never exercised.

Fix direction: pass the connection `host` as the servername to `upgradeToTls`;
keep `"helm.local"` only as the EHLO argument. Add a STARTTLS test that asserts
the servername. Filed: **HELM-P2-R11-F2**.

### P2-F3 — Credentials carried across egress redirects (Low, documented)

`performEgress` attaches the resolved credential to headers once (connector.mjs:206)
and re-sends `Authorization`/`X-Api-Key` (and the body) to redirect `Location`
targets on later hops. Every hop must still be in the contract allowlist, so this
cannot exfiltrate to an arbitrary host — but for a connector that allowlists two
hosts, host-A's credential is sent to host-B on a 3xx. Accepted for the MVP
(single-host connectors dominate; targets are operator-declared); revisit if a
multi-host connector ships. Recommend dropping auth headers when a redirect
changes host, and not re-sending the body on 301/302/303.

## C1 verdict — a compiled pack CANNOT smuggle I/O (PASS)

A compiled pack is pure data:

- The manifest hardcodes `connectors: []` and `actions: []`
  (`compile-packs.mjs:85-86`) — a compiled pack declares **zero** egress and
  zero side-effecting actions; there is no field through which network code
  could ride.
- A chain compiles **only** if every step's `tool_id` resolves to a kernel that
  is both `gpu:false` in the pinned chaingraph and vendored into
  `hub/vendored/ocg/kernels` — the exact registry `kernel-runner.mjs` enforces
  at run time. Any non-kernel node (browser widget, composer, arbitrary code) is
  skipped with a logged reason, never emitted.
- Each node pins `kernel_digest` = the vendored kernel's own sha256; the runner
  re-verifies against `MANIFEST.json`, so compile-time and run-time cannot drift.
- The manifest is schema-validated (`workflow-manifest.schema.json`) before write.

Non-blocking note: `name` and `outcome` are free-text copied from the pinned
(first-party) chaingraph and are rendered in Choose/Canvas — **P2-U4 must escape
them on render** (defense-in-depth; source is pinned + first-party, so not a
finding here). Freshness is gated (`--check`, 207 compiled / 102 skipped at
pinned `bfa1bd6`); skips are enumerated in `INDEX.json` (ABSENCE-INSTRUMENT).

## §10 gate 3 — HOLDS

> a user-declared outbound-HTTP connector reaches only its allowlisted host;
> unapproved host blocked + transcript-logged; secret never in log/export
> (grep-gate); zero traffic to ainumbers.co.

- Allowlist enforcement + blocked-and-journaled: `connector.test.mjs`,
  `http-send.test.mjs` (green).
- Secret never in log/export: `vault-secret-gate.test.mjs` (green).
- Zero ainumbers.co traffic: connectors call operator-declared hosts directly;
  no site/worker origin in any connector or egress path.

Full suite: **169 pass / 0 fail / 4 skip** (skips = live-net, gated behind
`HELM_LIVE_NET`); `lint: OK`; `compile-packs --check: fresh`.

## Residual risk statement (Phase 2)

No exploitable finding is left open: **P2-F1** and **P2-F2** are filed as board
rows (`HELM-P2-R11-F1`, `HELM-P2-R11-F2`); **P2-F3** is an accepted, documented
low. Until F1 lands, the resolved-IP deny list should be understood as defeating
static-misconfig and IP-literal SSRF but **not** an active-DNS-rebinding attacker
who controls an allowlisted host. Until F2 lands, SMTP STARTTLS AUTH should be
treated as unverified for cert-hostname binding (implicit `secure:"tls"` is
unaffected).
