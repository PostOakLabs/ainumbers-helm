# DNSSEC + CAA runbook — `ainumbers.co` zone (Cloudflare console)

**TIM-EXECUTED ONLY.** Per SO #8 (console fence) and SO #24 (zone-config
memorialization), no build session touches this console. This doc is the
exact-click sequence to hand-run in the Cloudflare dashboard. After
running it, paste back what actually landed (screenshots or the exact
values shown) so this WU's session can write the before/after memory in
the same sitting — an un-memorialized zone change is a standing drift
risk per SO #24.

**Verified "before" state (2026-07-24, via DNS-over-HTTPS query, not
console access):** no `DS` record for `ainumbers.co` at the registrar,
no `CAA` record in the zone, `DNSKEY` query returns no answer — DNSSEC
is currently **off**, CAA is currently **unset** (any CA may issue).

Registrar for `ainumbers.co` is whatever is configured outside
Cloudflare (Cloudflare is the DNS/nameserver operator per the earlier
`co` NS delegation) — confirm which registrar UI holds the DS-record
field before starting; if Cloudflare is also the registrar
(Cloudflare Registrar), steps 1–4 happen in one place and step 5 is
skipped.

---

## Part A — DNSSEC

1. Log in to the Cloudflare dashboard → select the **ainumbers.co** zone.
2. Left sidebar → **DNS** → **Settings** tab (not the Records tab).
3. Find **DNSSEC** → click **Enable DNSSEC**.
4. Cloudflare displays a DS record: `Key Tag`, `Algorithm`, `Digest Type`,
   `Digest` (also shown as one combined DS string). **Copy this exact
   value** — do not retype it from a screenshot, copy-paste to avoid a
   transcription error that would break resolution.
5. Go to the domain's **registrar** (wherever `ainumbers.co` itself was
   registered — check if that's Cloudflare Registrar or an external
   registrar):
   - **If Cloudflare Registrar:** Dashboard → **Domain Registration** →
     ainumbers.co → the DS record from step 4 is usually added
     automatically once DNSSEC is enabled in step 3 — confirm it shows
     under the registration's DNSSEC section; if not, add it manually
     with the same UI as below.
   - **If external registrar:** log in to that registrar's control
     panel → find the domain's **DNSSEC** or **DS records** section →
     **Add DS record** → paste the Key Tag / Algorithm / Digest Type /
     Digest values from step 4 exactly as Cloudflare displayed them →
     Save.
6. Wait for propagation (can take minutes to a few hours depending on
   the parent `.co` TLD's refresh interval). Verify with:
   ```
   curl -s "https://cloudflare-dns.com/dns-query?name=ainumbers.co&type=DS" -H "accept: application/dns-json"
   ```
   A non-empty `Answer` array (not just an `Authority` referral to
   `co`'s nameservers) confirms the DS record is live.
7. Back in the Cloudflare DNS Settings tab, DNSSEC status should read
   **Active** (green) once the parent zone has the DS record and
   Cloudflare has validated it — this can lag step 6's DNS propagation
   by a further few minutes.

**Rollback if something breaks resolution:** Cloudflare DNS Settings →
DNSSEC → **Disable DNSSEC**, then remove the DS record at the registrar.
Removing DS first (before disabling in Cloudflare) risks a validation
failure window — always disable in Cloudflare first, DS-removal second.

## Part B — CAA

1. Same zone → left sidebar → **DNS** → **Records** tab (the normal
   records list, not Settings).
2. Click **Add record**.
3. Type: **CAA**. Name: `@` (apex, i.e. `ainumbers.co` itself).
4. Add one record per authorized CA. Cloudflare issues certs itself
   (Universal SSL / Advanced Certificate Manager) — check which CAs are
   actually in use before restricting: Cloudflare's default issuance
   uses **Google Trust Services**, **Let's Encrypt**, and **SSL.com**
   as configurable options (dashboard → SSL/TLS → Edge Certificates →
   shows which CA issued the current cert — check this first so the CAA
   record doesn't accidentally lock out the CA actively issuing your
   cert).
5. Minimum recommended set (adjust to match step 4's finding):
   - Flags: `0`, Tag: `issue`, Value: `letsencrypt.org`
   - Flags: `0`, Tag: `issue`, Value: `pki.goog` (Google Trust Services)
   - Flags: `0`, Tag: `issuewild`, Value: `letsencrypt.org` (only if
     wildcard certs are used anywhere on the zone — check SSL/TLS →
     Edge Certificates for any `*.ainumbers.co` cert first)
   - Optional: Flags: `0`, Tag: `iodef`, Value:
     `mailto:security@postoaklabs.com` (per SO #C2's VDP contact,
     receives reports of unauthorized issuance attempts)
6. Save each record. TTL: Auto (Cloudflare-managed).
7. Verify:
   ```
   curl -s "https://cloudflare-dns.com/dns-query?name=ainumbers.co&type=CAA" -H "accept: application/dns-json"
   ```
   The `Answer` array should list the CAA records just added.

**Caution:** if any subdomain (`mcp.ainumbers.co`, `anchor.ainumbers.co`)
uses a *different* CA than the apex records cover, either add that CA to
the apex CAA set (CAA is inherited down the tree unless a subdomain has
its own CAA records) or add subdomain-specific CAA records. Check
SSL/TLS → Edge Certificates for each host before finalizing step 5's CA
list — a CAA record that excludes the CA currently issuing a live cert
will not revoke that cert immediately, but will block its next renewal.

---

## After running both parts

Paste back to the WU session:
- Whether DNSSEC now shows **Active** in Cloudflare DNS Settings, and
  the DS record values actually submitted at the registrar.
- The exact CAA records added (flags/tag/value for each).
- Confirmation from a follow-up DNS-over-HTTPS check (`DS` and `CAA`
  queries above both returning non-empty `Answer` arrays) — the session
  will re-run these before writing the memory entry, but your own
  confirmation speeds that up.
