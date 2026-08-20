# HELM-MATTER-SPEC  -  Matter Workspace for AINumbers Helm

**Date:** 2026-08-20 · **Status:** DRAFT (spec only, no build yet) · **Supersedes:** an earlier internal-workspace draft of the same spec (2026-08-08), now historical  -  this file is the live spec.
**Amendment basis:** a fresh review found three real interop anchors the earlier draft predated (a legal-matter tagging ontology, a court e-bundle formatting standard, and an eDiscovery load-file standard), verdict: worth building  -  pure data-model work with three credibility hooks against real external standards.
**Anchors:** `docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md` §"What gets signed" for the actual DSSE/envelope code this spec reuses, plus three interop anchors pinned this revision, each with source URL, retrieval date, sha256, and section references: `research/clause-snapshots/SALI-LMSS.citations.md`, `research/clause-snapshots/CTJ-general-guidance-electronic-court-bundles-2021-11-29.citations.md`, `research/clause-snapshots/EDRM-production-standards-v2.citations.md`.
**Gate:** does not touch `repo/chaingraph/standard/SPEC.md`.

---

## §0 What changed in this amendment, and why

The earlier draft was right about the shape (Helm-local matter container, bind-by-hash, offline verify) but predated three real interop anchors a fresh search found. Every behavioural rule, threshold, and enum value that touches a published external standard should cite the section of that standard it implements, backed by a locally pinned, hash-verified copy of the primary text rather than a paraphrase  -  the same discipline other standards-implementing specs in this codebase already follow, since a spec built off a stale or wrong reading of a standard costs far more to unwind after code exists than before. This revision retrieves and pins that primary text before any build work starts, and rewrites §2/§5 to bind to it instead of the earlier draft's placeholder design. Everything else in the earlier draft (§0 hosted-form kill, §3 binding-by-hash discipline, §4 verify-page shape, §6 non-goals) stood up under the amendment and is carried forward with citations added where it now touches primary text.

**The three anchors, folded in:**
- **SALI LMSS** (§2)  -  matter manifests carry LMSS tag IRIs (`http://lmss.sali.org/R<opaque>`), not invented local codes. Pinned: `SALI-LMSS.citations.md`.
- **UK e-bundle export shape** (§5)  -  export includes a paginated, bookmarked, single-PDF index matching the numbered rules of the CTJ "General Guidance on Electronic Court Bundles" (29 Nov 2021). Pinned: `CTJ-general-guidance-electronic-court-bundles-2021-11-29.citations.md`. **Naming correction from the triage doc:** the triage shorthand called this "CPR PD 5C"  -  PD 5C itself only governs CE-File format/size, not the pagination/bookmark rules; the actual numbered rules a matter export follows are the CTJ guidance, cited by its own paragraph numbers below (see the citations file's "Note on the anchor label" for the full distinction).
- **EDRM DAT-flavour manifest** (§5)  -  the eDiscovery-interchange-shaped sibling export uses EDRM's own 24-field metadata list, not an invented field set. Pinned: `EDRM-production-standards-v2.citations.md`.

**Zero new crypto, unchanged from the draft:** every signed matter object reuses Helm's existing DSSE envelope exactly as built  -  in-toto Statement v1, JCS-canonical payload, Ed25519 mandatory + ML-DSA (FIPS 204, parameter set 44) co-signature (`hub/envelope.mjs`, documented in `docs/HELM-TECHNICAL-DESIGN-IMPLEMENTATION.md` §"What gets signed")  -  and the existing bundle assembler (`hub/bundle.mjs:assembleBundle`). This spec introduces no signing scheme, no key type, no verification algorithm.

## §1 Field-coverage checklist (unchanged from the 08-08 draft  -  CounselOS borrow, practitioner input, not a schema)

`eigenlegal/counsel-os` (MIT, practicing-lawyer-built) ships a working matter-file shape, used here as a checklist against our own design, not copied as a schema.

| CounselOS concept | Covered by | Notes |
|---|---|---|
| Matter-id + stage enum (`intake\|working\|closed`) | §2 `matter.status` | Closed additionally triggers §5 bundle emission. |
| Structured deadline records `{date, action, type, source, done}`, `done:true` NEVER-DELETE | §2 `matter.deadlines[]` | A satisfied deadline record is never removed, only appended-over  -  no silently-false duty. |
| Sections: Parties / Documents / Context / Findings / Decisions / Open-Issues / Next-Action | §2 `matter.parties[]`, `matter.bindings[]`, `matter.narrative` | Findings/Decisions are NOT reproduced as free narrative  -  they are already first-class OCG artifacts (§27 approval/annotation records) referenced by hash. |
| Closeout = git-commit | §5 closeout hook | Ours: `status → closed` emits a DSSE-signed evidence bundle instead of a commit. |

## §2 Matter manifest schema (design, not JSON Schema text  -  the schema WU below authors the file)

A matter manifest is a Helm-local artifact  -  **not** an OCG chaingraph artifact, **not** submitted to `SPEC.md`  -  living in `helmd`'s SQLite store (same durability layer as runs, HELM-PHASE1-BUILD-SPEC D4) and exported as a directory-rooted JSON manifest. Fields:

- `matter_id`  -  Helm-local opaque ID (ULID), never derived from or colliding with any `execution_hash`.
- `status`  -  closed enum: `intake | working | closed`. Transition to `closed` is the only status transition with a side effect (§5).
- `entity`  -  the reporting entity this matter concerns, `{ id, lei? }`  -  reuses the §9 identity shape already normative for OCG identities; no new identity vocabulary.
- `regime`  -  free-text label naming the applicable regime/exam/filing (e.g. "NYDFS 23 NYCRR 500 exam prep 2026")  -  deliberately not a closed enum (mirrors §27.2's `reason_code` open-vocabulary rationale).
- `lmss_tags[]`  -  **new this amendment.** Array of SALI LMSS IRIs, each a string of the form `http://lmss.sali.org/R<opaque-id>` (pinned shape: `SALI-LMSS.citations.md`, "Namespace / IRI shape"). Zero or more per matter. **Validation rule:** a `lmss_tags[]` entry MUST match the IRI shape exactly  -  the pinned snapshot's own `dc:identifier` short codes (e.g. `ASI-TH-TH+24`) are explicitly NOT valid manifest values; they are SALI's internal display code, not the stable identifier (pinned snapshot, "Consequence for the spec"). The schema WU's fixture set includes one golden LMSS IRI and one tampered fixture using a short code instead of an IRI, expected to fail validation. No local matter-type taxonomy is invented  -  LMSS is the only closed vocabulary for what kind of matter/party-role/practice-area this is, exactly as the row's "invent no local codes" instruction requires.
- `parties[]`  -  `{ identity: {id}, role }` where `role` is free text ("examiner", "counsel", "client contact")  -  NOT the §27.1 closed accountability-role vocabulary, and NOT drawn from `lmss_tags[]` (a party role and a matter's substantive LMSS classification are different axes; conflating them was rejected  -  a matter tagged with an LMSS litigation-type IRI does not imply every party has an LMSS-coded role). Where a party IS also acting as a §27 preparer/reviewer/approver on a bound artifact, that role binding lives on the §27 record itself, referenced via `bindings[]`  -  never duplicated here.
- `deadlines[]`  -  `{ date, action, type, source, done, done_at? }`, CounselOS-shaped (§1). `done:true` records are append-only.
- `bindings[]`  -  the core of the design, unchanged from the draft. Each binding is `{ subject_hash, subject_kind, note? }`:
  - `subject_hash`  -  a `sha256:`-prefixed reference to an EXISTING artifact  -  a §4 `execution_hash`, a §27.2 approval record's own `execution_hash`, or a §27.4 non-node attested-artifact `execution_hash`. A binding never contains a payload copy.
  - `subject_kind`  -  closed enum: `run` \| `evidence_bundle` \| `approval_record` \| `attested_artifact` \| `external_reference`. `external_reference` is the only kind that may point at content Helm never verified and MUST be labeled distinctly in every rendering (§26.6 trust-label discipline, never collapsed into "verified").
  - `note`  -  free text, optional, never a substitute for a §27 annotation record.
- `narrative`  -  OPTIONAL free-text field for matter-level context not belonging to any one bound artifact. Not a place to restate Findings/Decisions that already exist as §27 records.
- `created_at` / `updated_at`  -  ISO 8601, Helm-local wall-clock.
- `manifest_digest`  -  a JCS digest of the manifest's own content, using the same `_hash.mjs` canon vendored per HELM-PHASE1-BUILD-SPEC D3.

**Directory-rooted storage** (this amendment's naming, per the triage verdict's "directory-rooted JSON manifest"): a matter's on-disk export unit is a directory  -  `matter.json` (the manifest above) at the root, plus one subdirectory per non-`external_reference` binding holding that binding's already-shipped export form (§5). This is the container the §4 verify page and the §5 export/closeout hook both operate on; it is a naming convention for how `helmd` lays out what §5 already assembles, not a new storage format.

**Additivity discipline, unchanged:** nothing above touches any existing `execution_hash` preimage, `$defs/artifact.required`, or `chaingraph_version`. A matter is purely a Helm-local index over already-sealed artifacts.

## §3 Binding model  -  reference by hash, never copy (unchanged from the 08-08 draft)

A matter binds **existing** helmd runs and evidence bundles. It does not re-run anything, does not re-derive an `execution_hash`, and does not store a second copy of any artifact payload. `helmd`'s run engine (HELM-H4) and evidence-bundle assembler (`hub/bundle.mjs`, HELM-H7) already produce content-addressed, hash-identified outputs; a matter binding is a foreign-key-by-hash into that existing store, resolved locally at export time  -  the same discipline §27.2 approval records already use toward their `subject_hash`.

## §4 Site verify page  -  read-only, no daemon required (unchanged from the 08-08 draft)

A new page in the site's Verify family (`repo/tools/` or `repo/chaingraph/` per existing Verify placement conventions  -  the WU below resolves the exact directory) that:

- Accepts a matter export directory (as a zip, drag/drop or file picker  -  client-side only, `CONTRACT.md`:22 in-memory-state rule applies).
- Verifies `manifest_digest`, then walks `bindings[]` and verifies each bound artifact using ALREADY-SHIPPED verification code (§27.6 evidence-bundle verification, §16 whole-artifact proof verification, §20 anchor verification, and the DSSE envelope verification already built in `hub/envelope.mjs` for the export's own signature).
- Surfaces exactly which bindings verified, which are `external_reference` (never verified, always labeled), and which deadlines are open  -  never collapsing into a single "matter verified ✓" badge.
- Works fully offline from an export file, standalone, no Helm daemon reachable  -  mirrors HELM-U3's Verify view design.
- Zero accounts, zero server storage, zero recurring manual duty.

## §5 Export design and the closeout hook  -  amended this row (LMSS/e-bundle/EDRM anchors bound in)

**Export = bundle-of-bundles**, unchanged core: the matter manifest (§2) plus, for every non-`external_reference` `bindings[]` entry, the referenced artifact's own already-shipped export form. The manifest itself and the aggregate export are DSSE-signed exactly as `hub/bundle.mjs:assembleBundle` already signs evidence bundles  -  same envelope code, same key material, no new signing path.

**Two export flavours, both derived from the directory-rooted manifest, neither replacing it  -  this is the amendment's concrete deliverable:**

### §5.1 UK e-bundle-style paginated/bookmarked PDF index

A rendering of the matter's `bindings[]` (in a stable, deterministic order  -  insertion order, since re-sorting would be non-additive to an already-exported matter) as a single PDF, satisfying  -  and citing by paragraph number  -  the pinned CTJ guidance (`CTJ-general-guidance-electronic-court-bundles-2021-11-29.citations.md`):

| Behavioural rule | Cites |
|---|---|
| Single PDF file per bundle, not multiple | CTJ ¶1, ¶8 |
| Computer-generated pagination, starting at page 1, sequential to the last page, pagination matches PDF page numbers | CTJ ¶2 |
| Hyperlinked index; every significant document and section bookmarked, bookmark text includes the page number | CTJ ¶3 |
| Text-bearing pages carry a text layer (OCR'd if the source has none) | CTJ ¶4 |
| Default view / zoom is 100% | CTJ ¶6 |
| Resolution capped at 300 dpi; file size minimized | CTJ ¶9 |
| Filename contains a case/matter reference and a content indicator | CTJ ¶ (Filename, p.4) |

**What this PDF is, precisely:** an index/cover rendering over the matter's bindings  -  one bookmarked entry per binding, each entry's page(s) either embedding the bound artifact's own rendered form (where the artifact has a natural page rendering, e.g. an `evidence_bundle`'s human-readable summary) or a one-page stub citing the `subject_hash` and `subject_kind` (where it does not, e.g. a raw `attested_artifact`). This is new rendering logic, not a new verification algorithm  -  the PDF is a navigation aid over already-verified bindings, never itself the thing verified (the verify page in §4 verifies the underlying `bindings[]`/DSSE envelope, not the PDF's own bytes).

**Addition to open deadlines discipline (carried from CounselOS checklist, §1):** if the matter has open (`done:false`) deadlines at export time, the e-bundle index MUST surface them unredacted at the front of the bundle  -  an examiner's first question. This is a spec-level requirement, not sourced from CTJ (CTJ has no deadline concept); it is Helm's own addition to the export, stated here so it is not lost.

### §5.2 EDRM-flavour DAT manifest

A sibling flat-file export  -  one row per `bindings[]` entry  -  using the field list pinned in `EDRM-production-standards-v2.citations.md`, mapped from the matter binding as follows (only fields with a real matter-side source are populated; the rest are emitted empty, never fabricated):

| EDRM field | Matter-side source |
|---|---|
| `DOCID` | `bindings[].subject_hash` (the `sha256:` string itself  -  content-addressed, so this is a materially better DOCID than an arbitrary sequence number) |
| `PARENTID` | if the bound artifact records a parent relationship (e.g. an approval record's own subject)  -  otherwise empty |
| `RCRDTYPE` | `bindings[].subject_kind` (`run` / `evidence_bundle` / `approval_record` / `attested_artifact` / `external_reference`) |
| `HASH` | same value as `DOCID` here  -  both are the sha256 content hash; kept as two columns because that is the EDRM field name a receiving eDiscovery platform expects |
| `DATECREATED` | the bound artifact's own creation timestamp where the artifact records one; otherwise empty |
| `CUSTODIAN` | the matter's `entity.id` |
| `FILENAME` / `DOCLINK` | the export directory's per-binding subdirectory path (§2 "Directory-rooted storage") |
| all remaining EDRM fields (`AUTHORS`, `BATES RANGE`, `BCC`, `CC`, `DATERECEIVED`, `DATESAVED`, `DATESENT`, `DOCEXT`, `FOLDER`, `FROM`, `SUBJECT`, `THREAD ID`, `TIMERECEIVED`, `TIMESENT`, `TO`, `ATTACHMENTIDS`) | emitted present-but-empty  -  a matter binding is not email-shaped, these are EDRM's email-oriented fields, kept only so the row count and column set match what a receiving Concordance/EDRM-XML importer expects |

**Delimiter note:** the pinned EDRM page documents the field list, not the physical delimiter bytes. Per the pinned citations file's own note, the Concordance-style pilcrow/thorn/caret delimiter convention is documented industry tooling practice, not EDRM primary text  -  the export format spec here is: field-delimited, one row per binding, header row naming the fields above, delimiter and quoting to be fixed by the schema WU against a real Concordance/Relativity import test (not invented here), and stated honestly as tooling convention rather than misattributed to an EDRM paragraph that does not exist.

**Closeout hook (unchanged from the draft  -  the integration prize):** `matter.status → closed` is specified to emit both export flavours (§5.1, §5.2) automatically alongside the existing evidence-bundle export, as one event, not a manual/polling duty. `helmd` emits it locally on the status transition; no external service is contacted. The design leaves a hook point for an external tool's own closeout event to trigger this via Helm's local MCP `evidence.export` endpoint or CLI.

## §6 Non-goals (explicit, per the row's fence  -  unchanged, extended for this amendment)

- No SPEC.md edit. If a normative artifact TYPE for matter containers is ever needed, that is a follow-on SPEC-SERIAL-class WU, named here, not drafted now.
- No hosted matter storage, no accounts, no server-side state.
- No new identity, role, or hashing scheme  -  every reference reuses §9 identity, §27 accountability shapes, the one `_hash.mjs` canon, and the existing `hub/envelope.mjs` DSSE signing.
- **No new LMSS ontology or local matter-type taxonomy**  -  `lmss_tags[]` is the only classification vocabulary; a matter with no applicable LMSS tag simply has an empty array, it does not get a locally-invented substitute code.
- No PDF/CPR-PD-5C-shaped bundling logic beyond §5.1's navigation-aid rendering  -  the e-bundle PDF is not submitted to any court by Helm itself; a practitioner uses it as a starting bundle and remains responsible for court-specific compliance.
- No recurring manual duty and no time/SLA promise anywhere in the design.

## §7 Work-unit list  -  amended field/dependency detail, same 5-row shape

All rows below are downstream of HELM-PHASE1-BUILD-SPEC's own WUs. Every helm-touching row inherits the standing re-vendor prerequisite (check mirror currency before the row starts, per `feedback-revendor-before-helm-work` doctrine).

| WU | Class | Title | Contract (summary) | Depends on | Re-vendor note |
|---|---|---|---|---|---|
| HELM-MATTER-S1 | S | Matter schema | Author `schema/matter-manifest.schema.json` per §2 (closed enums: `status`, `bindings[].subject_kind`; open: `regime`, `parties[].role`, `deadlines[].type`, `narrative`; `lmss_tags[]` IRI-shape validated against the pinned `SALI-LMSS.citations.md` pattern). Golden + tampered fixtures: a binding whose `subject_hash` doesn't resolve; a re-derived `manifest_digest` mismatch; an `lmss_tags[]` entry using a SALI short code instead of an IRI (must fail). | HELM-S1 | Yes  -  cites vendored `_hash.mjs` conventions; confirm mirror before authoring `manifest_digest` fixtures. |
| HELM-MATTER-H1 | H | Matter store + CRUD | `helmd` SQLite table for matters (HELM-H4's durability layer, D4), CRUD over the §2 manifest, `bindings[]` resolution against existing run/evidence-bundle/approval-record stores (§3), validation that every non-`external_reference` binding resolves before acceptance, directory-rooted export layout (§2). | HELM-MATTER-S1, HELM-H4, HELM-H7 | Yes. |
| HELM-MATTER-H2 | H | Closeout export hook + dual-flavour export | `status → closed` emits (a) the evidence-bundle-of-bundles per §5, (b) the §5.1 CTJ-cited PDF index, (c) the §5.2 EDRM-flavour DAT manifest  -  all DSSE-signed via existing `hub/envelope.mjs`/`hub/bundle.mjs`, no new signing code. Local MCP `evidence.export` extension (HELM-H9 dependency) and CLI trigger path for external-tool closeout integration. | HELM-MATTER-H1, HELM-H9 | Yes. |
| HELM-MATTER-U1 | U | Matter UI in helm.html | A Matters view (list, open/closed filter, deadline surfacing, binding browser, LMSS tag picker sourced from the pinned LMSS snapshot) inside the existing HELM-U1/U2 shell  -  dormant-state rendering when daemon absent, ANTI-AI-TELL copy ban applies. | HELM-MATTER-H1, HELM-U1 | Yes. |
| HELM-MATTER-VERIFY | X | Site matter-verify page | Read-only client-side matter-export verifier per §4, in the site repo's Verify family. Site-repo work item (`PostOakLabs/ainumbers`, `main`), not a helm-repo change. Screenshot of the rendered page required at check-off. | HELM-MATTER-S1, HELM-H7 | No  -  site repo only. |

**Sequencing:** S1 → {H1 → H2 (after H9) ∥ U1} → VERIFY-1. Five WUs, none SPEC-SERIAL, none reserving an artifact number.

## §8 Done criteria for this spec row

- ✓ Matter manifest schema (§2) amended with `lmss_tags[]` (SALI LMSS IRI shape, pinned) and directory-rooted storage naming, binding-by-hash model (§3) unchanged.
- ✓ Export design (§5) amended: §5.1 UK e-bundle-style PDF index citing CTJ guidance ¶ numbers, §5.2 EDRM-flavour DAT manifest citing the EDRM 24-field list  -  every behavioural rule in both cites a pinned-snapshot paragraph or explicitly states there is none to cite.
- ✓ Zero new crypto confirmed against the actual signing code (`hub/envelope.mjs` DSSE, `hub/bundle.mjs`), not just asserted.
- ✓ Closeout→bundle hook folded in (§5), not left as a separate proposal.
- ✓ Cycle class: n/a  -  spec-only revision, no kernel involved.
- ✓ WU list (§7)  -  5 rows, each with class + fence + re-vendor note.
