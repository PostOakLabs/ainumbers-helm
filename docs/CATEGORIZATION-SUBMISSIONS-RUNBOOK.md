# Helm — Domain Categorization + Clean-File Submissions Runbook (Phase 3)

**Scope:** `HELM-P3-T14` (per `HELM-PHASE3-BUILD-SPEC.md` §2 + P3-DEC-4). Bank/managed-endpoint
proxies (Zscaler, Netskope, Bluecoat/Symantec) block "Uncategorized" domains by default —
`ainumbers.co` and `anchor.ainumbers.co` must be submitted for a business category before
a bank-desktop pilot can reach either origin. Separately, unsigned SEA binaries (P3-D2) get
flagged by Microsoft Defender/SmartScreen and should be submitted to Microsoft's clean-file
process per release.

**Ownership (P3-DEC-4, Tim 2026-07-23):** vendor category-submission forms want the
domain/company owner, not a build agent. **Every step below is TIM-EXECUTED.** This doc is
the runbook, not a completed submission — no agent should attempt these forms.

**Turnaround expectation:** category submissions are typically reviewed in **1–10 business
days** (vendor-dependent, no SLA); Microsoft's SEA clean-file loop is **2–4 weeks per
release** (per P3-D2/T14 row) since a new unsigned binary hash needs re-submission every
build.

---

## Domains to submit (both, every vendor)

- `ainumbers.co`
- `anchor.ainumbers.co`

**Suggested category:** Business / Business Applications (fallback: Financial Services /
Information Technology — pick whichever the vendor's taxonomy actually offers; do not
select "Uncategorized" workarounds like Proxy/Anonymizer).

---

## TIM-EXECUTED — Zscaler

1. Go to the Zscaler URL Category Lookup / recategorization request tool:
   `https://sitereview.zscaler.com/` (public tool; no account required to *submit*).
2. Enter `ainumbers.co`, review the current category shown, click **"Request Category
   Change"** (or **"Suggest a category"** if already Uncategorized).
3. Suggested category: **Business/Economy** (Zscaler's closest taxonomy match).
4. Repeat steps 2–3 for `anchor.ainumbers.co`.
5. Fill the requester email as `tim@postoaklabs.com` so confirmation/rejection replies land
   with the owner.
6. **Expected turnaround:** Zscaler states most requests process automatically within
   24–48h; contested/manual review can take up to ~10 business days.

## TIM-EXECUTED — Netskope

1. Go to Netskope's Cloud Confidence / URL lookup tool:
   `https://www.netskope.com/netskope-cloud-confidence-index/url-lookup` (or the current
   "Report a mis-categorized URL" form linked from netskope.com support).
2. Submit `ainumbers.co`, choose the closest category: **Business & Economy** (or
   **Financial Services** if offered as a distinct option — prefer the more specific one).
3. Repeat for `anchor.ainumbers.co`.
4. Netskope's public form typically requires an email for follow-up — use
   `tim@postoaklabs.com`.
5. **Expected turnaround:** no published SLA; Netskope support threads report ~5–10
   business days for public (non-customer) submissions. If a specific bank pilot uses
   Netskope, their Netskope admin can also submit via their own tenant console, which is
   usually faster — note this as an alternate path when a pilot bank is identified.

## TIM-EXECUTED — Bluecoat / Symantec (Broadcom WebPulse / Site Review)

1. Go to Broadcom's Site Review tool: `https://sitereview.bluecoat.com/`
   (legacy Blue Coat WebPulse categorization, now under Broadcom/Symantec).
2. Enter `ainumbers.co`, review current category, use **"Suggest a Category Change"**.
3. Suggested category: **Business/Economy** (fallback **Financial Services**).
4. Repeat for `anchor.ainumbers.co`.
5. The form requires a captcha + submitter email — use `tim@postoaklabs.com`.
6. **Expected turnaround:** Broadcom's own guidance says up to 24h for automated review,
   longer for manual escalation (no fixed SLA published).

---

## TIM-EXECUTED — Microsoft clean-file / SEA binary submission (per SEA release)

**Why:** the unsigned Node SEA binaries (P3-D2 "advanced" install path) are proactively
AV-flagged since the Oct 2025 Stealit-style campaign abused the same packaging technique.
Signing is deferred at $0 budget (P3-D1); until a signing cert exists, each release's SEA
binaries need an explicit clean-file submission so Defender/SmartScreen stop cold-blocking
first downloads.

1. After cutting a release (`helm/packaging`, SEA binaries built per `RELEASING.md`),
   compute the SHA256 of each platform binary (already produced by the release pipeline's
   `SHA256SUMS`, per P3-D1 free hardening).
2. Go to the Microsoft Security Intelligence submission portal:
   `https://www.microsoft.com/en-us/wdsi/filesubmission`
3. Submit **one ticket per binary** (Windows SEA `.exe` is the one that matters most for
   Defender/SmartScreen false-positive reports; submit macOS/Linux artifacts too if a
   corresponding vendor AV flags them):
   - Submission type: **Software developer**
   - File classification you're disputing: **Software developer** → "I believe this file
     is incorrectly detected" (false positive) if a specific product name is shown, or a
     plain new-file submission if nothing has flagged it yet but proactive review is wanted.
   - Attach the binary + note the SHA256 in the description for cross-reference.
4. Note the ticket/reference number Microsoft returns; if a specific detection name comes
   back later, that becomes the tracked "known FP" entry for that release version.
5. **Expected turnaround:** Microsoft's own guidance is **~2–4 weeks** for full review; the
   binary hash changes every release, so this is a **recurring per-release step**, not a
   one-time fix. Track it as a release-checklist line item in `RELEASING.md` until a signing
   cert (D-SIGN-2/3, still deferred) removes the need.

---

## What this runbook does NOT do

- It does not submit anything — every step above requires a human with authority to speak
  for `postoaklabs.com` / `ainumbers.co`, and vendor forms are captcha/email-verification
  gated in ways no agent should attempt.
- It does not track submission status — once Tim runs a step, log the outcome (accepted
  category / ticket number / rejection reason) back into this doc or a follow-up note so
  the next SEA release doesn't re-litigate a settled category.
- Delegation per P3-DEC-4: any step Tim can hand off (e.g., a bank pilot's own IT
  submitting via their tenant's Netskope console) is called out inline above; everything
  else stays owner-executed.
