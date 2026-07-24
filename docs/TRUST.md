# Helm trust page v1

This is the source for Helm's public trust posture. Eight parts, in order:
scoping, network behavior, a reproducible zero-telemetry check, the
data-flow/subprocessor statement, the per-release SBOM, zone-level DNS
hardening (DNSSEC + CAA), dated third-party grades for every host in §2,
and the Subresource Integrity statement. It extends
[HELM-P3-T13](https://ainumbers.co/trust/) (site-repo trust pages covering
CAIQ-Lite, threat model, LNA policy, PA coexistence) with the parts that are
specific to this repo's shipped code and release pipeline — read both; this
page does not restate T13's content.

## 1. SOC 2 scoping statement

SOC 2 attests that a **service organization** operates controls over
**customer data it holds**. Helm is not a service organization in that
sense: `helmd` is a daemon you run on your own machine, against your own
files, and Post Oak Labs never receives, stores, or processes your data.
There is no multi-tenant system on our side for an auditor to examine —
a SOC 2 report would describe infrastructure that does not exist.

What we provide instead, in lieu of a SOC 2 report:

- **This document** — an exhaustive, code-derived list of every network
  request the shipped binary or UI can make (§2), so you can verify the
  "local-first" claim yourself rather than take it on faith.
- **A reproducible zero-telemetry recipe** (§3) — run it yourself in ten
  minutes, on your own machine, against a real build.
- **A signed release manifest** (DSSE, `dist/release-manifest.dsse.json`)
  and GitHub build provenance attestation for every release binary —
  verifiable supply-chain integrity for the artifact you download, which
  is the part SOC 2 doesn't cover anyway.
- **A CycloneDX SBOM per release** (§5) — full dependency inventory, so
  your own vendor-risk process has real data instead of a questionnaire
  answer.

If your procurement process requires a SOC 2 report as a checkbox
regardless, say so — there is nothing here to substitute; the honest
answer is that the report doesn't apply to a tool with this deployment
model, and the four items above are the actual evidence.

## 2. Network-behavior doc — every outbound request

This table is authoritative because it was derived by reading the shipped
source directly, not from a design doc: every `fetch`/`http(s).request`
call under `hub/` and `ui/` (excluding tests, node_modules, generated
`dist/`), plus every hardcoded external hostname.

### Runtime calls (helmd / browser UI, normal use)

| # | Endpoint | Trigger | Payload |
|---|---|---|---|
| 1 | `POST https://anchor.ainumbers.co/relay/<ca>` | RFC 3161 anchoring of a checkpoint (`hub/anchor-client.mjs`, `anchorRfc3161`) | Raw TSQ DER built from the checkpoint's SHA-256 hash only — no document content |
| 2 | `POST https://{a,b}.pool.opentimestamps.org`, `https://alice.btc.calendar.opentimestamps.org/digest` | OpenTimestamps anchoring (`anchorOpenTimestamps`) | Raw SHA-256 digest bytes only |
| 3 | Connector-defined host (via `performEgress`, DNS-rebind checked, `redirect: manual`) | Any installed, signed connector contract | Whatever that connector's `send()` builds — scoped to its own allowlisted host |
| 4 | `GET https://www.googleapis.com/drive/v3/files/{fileId}?alt=media` | Google Drive fetch connector, user picks a file | OAuth bearer token (header, from vault) out; file bytes back, kept in-process |
| 5 | `POST {tokenEndpoint}` (RFC 8252 loopback PKCE); shipped preset `https://github.com/login/oauth/access_token` | User clicks "Connect" in the UI | Authorization code + PKCE verifier + client_id + redirect_uri — no client secret |
| 6 | `POST {revocationEndpoint}` (RFC 7009) | User clicks "Disconnect" | Token revocation only |
| 7 | Browser navigation to `https://github.com/login/oauth/authorize` | User clicks "Connect" | Standard OAuth authorize redirect — not a server-side call |
| 8 | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/{authorize,token}`, `https://accounts.google.com/o/oauth2/v2/auth`, `https://oauth2.googleapis.com/token` | Browser-only mode (no `helmd` installed), user connects a provider | PKCE code exchange; response tokens land in sessionStorage/vault |
| 9 | `GET https://api.github.com/user` with `Authorization: Bearer <pasted PAT>` | User pastes a fine-grained PAT to verify it | The pasted PAT, to GitHub only, to confirm it's valid |
| 10 | `GET https://ainumbers.co/helm/version.json` | Running `helmd doctor` | Nothing but the GET; response is a static version JSON (skew check) |
| 11 | `GET http://127.0.0.1:{port}/version` | Browser UI probing a local `helmd` for handoff | Loopback only — never leaves the machine |

**No telemetry, analytics, or crash-reporting library exists anywhere in
this repo.** (Checked for Sentry, PostHog, Segment, Mixpanel, and generic
beacon/analytics patterns — none found.)

### Present in code, not reachable at runtime today

- `anchorForCheckpoint` / `anchorRfc3161` / `anchorOpenTimestamps`
  (row 1–2 above) are exercised only by this repo's own tests today —
  `hub/checkpoint.mjs` does not call them and no route wires anchoring
  into a user-triggered path yet. Listed anyway because the code exists
  and is capable of making the call; update this doc the moment a WU
  wires it live.
- The Google Drive connector (row 4) is likewise only instantiated in
  its own test file — no runtime registry constructs it yet. The generic
  `performEgress` mechanism (row 3) is live for any connector that *is*
  installed.

### Build/release-time only (CI runners, never shipped in the binary)

- `git clone https://github.com/PostOakLabs/ainumbers.git` — source of
  `hub/vendored/ocg` (`scripts/vendor.config.json`).
- `git clone https://github.com/PostOakLabs/anchor-suite.git` — source
  of `hub/vendored/anchor-suite` (`scripts/vendor-anchor.config.json`).
- Standard GitHub Actions / npm registry / GH release-asset traffic in
  `.github/workflows/release.yml` — ordinary CI plumbing, not something
  the shipped daemon does.

## 3. Reproducible zero-telemetry recipe (≤10 minutes)

Verify §2 yourself rather than take our word for it:

1. Install `helmd` per [`INSTALL.md`](INSTALL.md) and start it:
   `helmd start`.
2. Open your browser's devtools **Network** tab, filter to
   "Other"/"Fetch/XHR", and open `helm.html` pointed at the running
   daemon.
3. Run a workflow end to end: load a template, execute a run, view the
   result canvas. Do **not** connect any OAuth provider and do **not**
   trigger an anchor/checkpoint action for this pass.
4. Observe the Network tab: the only entries should be
   `http://127.0.0.1:<port>/...` calls to your own local `helmd` (loopback,
   row 11 above) — nothing external.
5. Optionally repeat with `helmd doctor` running in a terminal at the
   same time and watch for exactly one call to
   `https://ainumbers.co/helm/version.json` (row 10) — the version-skew
   check, and the only thing that leaves the machine during ordinary
   use if you run `doctor`.
6. If you connect a provider or trigger an anchor, you'll see exactly
   the rows in §2 that describe those actions and nothing else — no
   additional hosts should ever appear.

If you observe a request to a host not listed in §2, that's a bug —
file it under [GitHub Security Advisories](https://github.com/PostOakLabs/ainumbers-helm/security)
per the VDP.

## 4. Data-flow / subprocessor statement

Post Oak Labs is **not a subprocessor** of your data. `helmd` runs on
your infrastructure, reads and writes your files, and no run data,
document content, or workflow output is ever sent to
`ainumbers.co` or any Post Oak Labs system. The only bytes that ever
leave your machine toward an AINumbers-operated endpoint are:

- A SHA-256 hash (never document content) to `anchor.ainumbers.co`,
  and only if you explicitly invoke anchoring (§2 rows 1–2 — currently
  not wired to any live path, see above).
- A version-check GET with no request body, only if you run
  `helmd doctor` (§2 row 10).

Everything else in §2 — OAuth connects, connector egress, PAT
verification — is a direct connection from your machine to the
third-party provider you chose (GitHub, Google, Microsoft, or a
connector's own declared host). Post Oak Labs is never in that data
path and never sees the payload.

**If you self-host the anchor relay or disable it entirely:** the
anchoring rows above become no-ops or point at your own infrastructure.
Embedders who want zero contact with any AINumbers-operated endpoint
should self-host equivalents of the anchor/OpenTimestamps calls or
disable checkpoint anchoring outright — nothing else in this repo talks
to us.

## 5. CycloneDX SBOM per release

Every tagged release (`v*`) generates a CycloneDX JSON SBOM covering the
full dependency tree, published as a release asset alongside the signed
release manifest and `SHA256SUMS`. See
[`.github/workflows/release.yml`](../.github/workflows/release.yml) (the
`sign-and-release` job's SBOM step) — generated with
[anchore/sbom-action](https://github.com/anchore/sbom-action), pinned by
commit SHA. Fetch the SBOM for any release from that release's GitHub
assets: `sbom.cyclonedx.json`.

## 6. Zone-level DNS hardening: DNSSEC + CAA

The `ainumbers.co` zone (Cloudflare-managed, covers every host in §2 —
`ainumbers.co`, `anchor.ainumbers.co`, `mcp.ainumbers.co`) runs DNSSEC and
CAA the way Cloudflare's own documentation recommends. Both are
zone-wide Cloudflare **console/registrar** toggles, not application
code — Post Oak Labs' standing operating rule (SO #8, SO #24) is that a
build session never touches production zone config directly; a human
applies console changes from a written runbook and the session
memorializes the before/after. The exact-click runbook for this WU's
DNSSEC + CAA change lives in
[`DNSSEC-CAA-RUNBOOK.md`](DNSSEC-CAA-RUNBOOK.md) in this directory.
Current state as verified by this WU (`dig`/DNS-over-HTTPS, 2026-07-24):
no `DS` record at the registrar and no `CAA` record in the zone — both
pending the runbook's execution. This section will be updated with the
landed state once Tim confirms.

## 7. Third-party grades — dated, every host in §2

Run against the live sites, not against a design doc. Re-run and
re-date whenever the CSP/header baseline changes materially; a stale
grade is worse than no grade, so don't let this table silently drift.

| Host | Qualys SSL Labs | Mozilla/MDN HTTP Observatory | Scanned |
|---|---|---|---|
| `ainumbers.co` | **B** (all 4 endpoints) | **C+** (60/100, 8/10 passed) | 2026-07-24 |
| `mcp.ainumbers.co` | **A+** (all 4 endpoints) | **C** (55/100, 8/10 passed) | 2026-07-24 |
| `anchor.ainumbers.co` | **B** (all 4 endpoints) | **A+** (135/100) | 2026-07-24 |

SSL Labs: [ainumbers.co](https://www.ssllabs.com/ssltest/analyze.html?d=ainumbers.co) ·
[mcp.ainumbers.co](https://www.ssllabs.com/ssltest/analyze.html?d=mcp.ainumbers.co) ·
[anchor.ainumbers.co](https://www.ssllabs.com/ssltest/analyze.html?d=anchor.ainumbers.co).
Observatory: [ainumbers.co](https://developer.mozilla.org/en-US/observatory/analyze?host=ainumbers.co) ·
[mcp.ainumbers.co](https://developer.mozilla.org/en-US/observatory/analyze?host=mcp.ainumbers.co) ·
[anchor.ainumbers.co](https://developer.mozilla.org/en-US/observatory/analyze?host=anchor.ainumbers.co).

**What's holding `ainumbers.co` and `mcp.ainumbers.co` at C/C+ (both
share the same two failing Observatory tests):**

- **`content-security-policy`** — implemented but with `'unsafe-inline'`
  in `script-src`/`style-src`, so it scores as "implemented unsafely"
  (−20 to −25). Tightening this is a real content change (removing
  inline script/style), not a config toggle — out of scope for this WU;
  tracked as a follow-up, not silently fixed here.
- **`x-frame-options`** — not set (−20). The site deliberately leaves
  framing policy to CSP `frame-ancestors` rather than the legacy header;
  Observatory scores the legacy header's absence regardless. Documented
  here rather than added reflexively — SO #20 (`connect-src 'self'
  https:`) already governs this surface; adding XFO is a separate call
  for whoever owns CSP policy, not this WU.

`anchor.ainumbers.co` (BrowserChain/anchor-suite host) has neither
Observatory gap — A+/135 — because it serves no HTML/JS surface to
harden. Its **SSL Labs B** (shared with `ainumbers.co`) has a different,
confirmed cause: the endpoint still negotiates **TLS 1.0/1.1** alongside
1.2/1.3 (SSL Labs caps the grade at B whenever legacy TLS versions are
enabled, independent of cipher strength). `mcp.ainumbers.co` (the
Cloudflare Worker) doesn't offer TLS 1.0/1.1 and scores A+ — the gap is
the zone/edge-certificate **Minimum TLS Version** setting, another
Cloudflare console toggle, not application code. Raising it to TLS 1.2
is out of scope for this WU (it's a separate console change with its
own blast radius — could break legacy clients still connecting over
1.0/1.1) but is flagged here as a follow-up candidate, not silently
applied.

## 8. Subresource Integrity (SRI) statement

**N/A by construction.** Grepped every `.html`/`.mjs`/`.js` file in this
repo (excluding `node_modules`, generated `dist/`, and vendored kernel
fixtures) for `<script src=` and `<link href=` pointing at an external
origin — zero matches. `ui/helm.html` and `ui/oauth-callback.html` load
no third-party script or stylesheet at all; every dependency (pptxgenjs,
dmn-js, etc.) is vendored and bundled in-repo, not fetched at runtime.
`ui/lib/standalone-verifier.test.mjs` asserts this holds for the
standalone verifier's self-contained HTML output too — the test fails
if any `<script src=` is ever introduced. Because there is no
cross-origin script/style load to protect, an SRI `integrity` hash has
nothing to attach to; this statement is re-derived by re-running the
grep, not asserted from memory, and will flip to a hash table the day
any cross-file load is added.
