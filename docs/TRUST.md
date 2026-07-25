# Helm trust page v1

This documents Helm's network and supply-chain behavior. Seven parts, in
order: network behavior, a reproducible zero-telemetry check, the data-flow
statement, the per-release SBOM, zone-level DNS hardening (DNSSEC + CAA),
dated third-party grades for every host in §1, and the Subresource
Integrity statement.

## 1. Network-behavior doc — every outbound request

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
| 10 | `GET https://ainumbers.co/helm/version.json` | **On by default.** Fired by helmd itself, on behalf of row 12 below, once on every UI boot and then every hour (`ui/app.mjs` `checkSkew()` + `setInterval(checkSkew, 60*60*1000)`, relayed by `hub/server.mjs` `GET /version-check`). Also fired once, separately, whenever `helmd doctor` runs (`hub/doctor.mjs`). | Bare GET, no request body, no identifiers, no user or workflow data. Response is a static version-notice JSON (`schema/version_notice.schema.json`) used only to show a passive "an update exists" banner — never downloaded or applied automatically (D10). Like any HTTP request it necessarily reveals the caller's IP and User-Agent to the server. **Disable:** set `"versionCheckUrl": ""` (or omit and let a falsy value pass) in `~/.helm/config.json` (`hub/config.mjs`) — `hub/server.mjs`'s `GET /version-check` handler then returns `{ checked: false, reason: "disabled" }` without making row 10's outbound call at all. |
| 11 | `GET http://127.0.0.1:{port}/version` | Browser UI probing a local `helmd` for handoff, only on explicit user click, never on page load | Loopback only — never leaves the machine |
| 12 | `GET http://127.0.0.1:{port}/version-check` | Browser UI, authenticated loopback call that triggers row 10 above: once on boot, then hourly (`ui/app.mjs`) | Loopback only — never leaves the machine; the outbound leg it triggers is row 10 |

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

## 2. Reproducible zero-unlisted-egress recipe (≤10 minutes)

Browser devtools cannot verify this repo's egress claim end to end: helmd's
outbound call to `ainumbers.co` (row 10) is made server-side, by the daemon
process, and can **never** appear in a browser's Network tab no matter how
zero-telemetry the app is — the tab only sees loopback traffic between the
UI and helmd (rows 11–12). A recipe built around watching devtools and
expecting silence is structurally incapable of proving or disproving §1;
verify it at the OS/process level instead, and expect to see row 10 fire,
not to see nothing.

1. Install `helmd` per [`INSTALL.md`](INSTALL.md) and start it:
   `helmd start`.
2. Start a machine-level egress observer *before* the daemon makes its
   first call — pick one:
   - `sudo lsof -i -P -n -p $(pgrep -f helmd)` (macOS/Linux, poll it, or
     use `watch`)
   - `sudo netstat -anp | grep $(pgrep -f helmd)` (Linux)
   - a host firewall/egress proxy rule scoped to the `helmd` process,
     logging connections instead of blocking them
3. Open `helm.html` pointed at the running daemon in a browser. Within a
   few seconds you should see exactly one outbound TCP connection from
   the `helmd` process to `ainumbers.co:443` — that's row 10, the
   version-check poll firing on UI boot. This is expected, not a leak.
4. Leave both running. No further outbound connection from `helmd` should
   appear until the hour mark, when row 10 fires again (or until you run
   a workflow, connect a provider, or trigger anchoring — each of which
   produces exactly the rows in §1 that describe that action).
5. To confirm row 10 is the *only* always-on background call: set
   `"versionCheckUrl": ""` in `~/.helm/config.json`, restart `helmd`, and
   repeat steps 2–4. Now zero outbound connections should appear at boot
   or at the hour mark — only connections you cause yourself (OAuth
   connect, anchor, connector egress) should ever show up.
6. Optionally also watch the browser's devtools **Network** tab in
   parallel: you'll only ever see `http://127.0.0.1:<port>/...` calls
   there (rows 11–12) — never `ainumbers.co` — because the outbound leg
   is made by helmd, not the browser. That's expected, and is why step 2
   uses a machine-level tool instead.

If you observe an outbound connection to a host not listed in §1, that's
a bug — file it under
[GitHub Security Advisories](https://github.com/PostOakLabs/ainumbers-helm/security)
per the VDP.

## 3. Data-flow statement

`helmd` runs on your own machine, reads and writes your files, and sends
no run data, document content, or workflow output to `ainumbers.co` or any
Post Oak Labs system. The only bytes that ever leave your machine toward an
AINumbers-operated endpoint are:

- A SHA-256 hash (never document content) to `anchor.ainumbers.co`,
  and only if you explicitly invoke anchoring (§1 rows 1–2 — currently
  not wired to any live path, see above).
- A version-check GET with no request body and no identifiers — sent
  by default, once on every UI boot and hourly thereafter, and also
  whenever you run `helmd doctor` (§1 row 10). Disable it by setting
  `"versionCheckUrl": ""` in `~/.helm/config.json`.

Everything else in §1 — OAuth connects, connector egress, PAT
verification — is a direct connection from your machine to the
third-party provider you chose (GitHub, Google, Microsoft, or a
connector's own declared host). Those bytes never traverse a Post Oak Labs
system.

**If you self-host the anchor relay or disable it entirely:** the
anchoring rows above become no-ops or point at your own infrastructure.
To have zero contact with any AINumbers-operated endpoint,
self-host equivalents of the anchor/OpenTimestamps calls or
disable checkpoint anchoring outright — nothing else in this repo talks
to us.

## 4. CycloneDX SBOM per release

The release pipeline generates a CycloneDX JSON SBOM and a `SHA256SUMS`
file for every tagged release going forward, published as release assets
alongside the signed release manifest. See
[`.github/workflows/release.yml`](../.github/workflows/release.yml) (`sbom`
+ `attach-sbom-asset` jobs; SBOM generated with
[anchore/sbom-action](https://github.com/anchore/sbom-action), pinned by
commit SHA). **v0.1.0 predates this pipeline and has neither asset** —
check a release's GitHub assets for `sbom.cyclonedx.json` /
`SHA256SUMS` before relying on either.

## 5. Zone-level DNS hardening: DNSSEC + CAA

The `ainumbers.co` zone (Cloudflare-managed, covers every host in §1 —
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
pending the runbook's execution.

## 6. Third-party grades — dated, every host in §1

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

## 7. Subresource Integrity (SRI) statement

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
