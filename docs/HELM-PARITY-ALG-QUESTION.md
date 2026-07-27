# The `alg` question — `'EdDSA'` vs `'Ed25519'` — RESOLVED 2026-07-25 (`EdDSA` normative)

**Status: resolved by the `## DETERMINATION (2026-07-25)` section below —
`"EdDSA"` is normative. An earlier fix shipped it for `hub/envelope.mjs`
`emitEnvelope()` + the schema enums, but never scoped
`hub/ha-gate.mjs`'s `signBundleDigest` (the maker-checker countersignature
path) — a second, independent producer of the same `{keyid,sig,alg}` shape
this document never audited. A follow-up fix (2026-07-27) corrected that
call site to match this determination.**

## What each side accepts

DSSE envelope signature entries carry an `alg` field
(`{keyid, alg, sig}`, see `hub/envelope.mjs` `emitEnvelope()`). Two
independent implementations look for the Ed25519 signature entry differently:

- **`hub/envelope.mjs` `verifyEnvelope()`** (line ~84): looks for
  `s.alg === "EdDSA"` only.
- **`ui/lib/verify-envelope.mjs` `verifyEnvelope()`** (line ~73, the browser
  Verify view's hand-mirror): looks for
  `s.alg === "EdDSA" || s.alg === "Ed25519"`.

`hub/envelope.mjs` `emitEnvelope()` itself always writes `"EdDSA"` — so this
divergence is currently latent (nothing in this repo emits `"Ed25519"`
today). It becomes live the moment ANY producer — a future integration, a
hand-crafted envelope, an external tool — emits `alg: "Ed25519"`: the browser
Verify view accepts it, the hub CLI/daemon path rejects the identical
envelope. That is a silent verifier disagreement over "is this envelope
valid," which is exactly the class of bug a parity gate exists to catch and
pin (`ui/lib/verify-parity-gate.test.mjs`, `expected-divergence 1`).

## Which name is "correct" is a standards question, not a preference

- **`EdDSA`** is the name registered for Ed25519 in
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) (JOSE/JWA — the `alg`
  header value for the Edwards-curve signature algorithm using Curve25519)
  and reused by COSE. It is the algorithm-family identifier the JOSE/COSE
  ecosystem standardized on; `crv: Ed25519` (or `Ed448`) is a separate field
  that names the *curve*, since `EdDSA` alone is curve-ambiguous.
- **`Ed25519`** names the curve/instantiation directly (RFC 8032's
  `Ed25519` signature scheme). It is not a registered JOSE `alg` value, but
  it appears as a value elsewhere — e.g. some `did:key`/multicodec and
  non-JOSE signing conventions identify the scheme this way, and it is more
  self-describing to a reader unfamiliar with JOSE's split naming.

Which one an envelope's `alg` field is REQUIRED to carry is fixed by
whichever signing envelope spec Helm's own bundles claim to follow — DSSE
(`https://github.com/secure-systems-lab/dsse`) — and, transitively, whatever
that spec says about JOSE/COSE `alg` registration. **DSSE's own spec and
examples use JOSE-style `alg` values** (its reference implementation and the
in-toto ecosystem it's paired with follow JOSE/COSE naming), which is why
`hub/envelope.mjs` emits `"EdDSA"` — but this write-up does not itself rule
on whether that makes `"Ed25519"` a nonconforming value that must always be
rejected, or a value some future producer is entitled to emit that all
verifiers must then accept.

## Which direction is lenient vs strict

- **Hub is STRICT**: rejects `alg: "Ed25519"` outright (no matching
  signature entry found → `ed25519: false` → envelope invalid).
- **Browser/`ui` is LENIENT**: accepts either spelling.

The lenient side is the more dangerous one to leave unresolved — a lenient
verifier is the one that can be tricked into accepting something a stricter
verifier (or a future, spec-compliant one) would reject. This write-up takes
no position on whether the fix is "make hub lenient too" or "make ui strict
to match hub" — that choice is exactly what needs a ruling, because it is a
statement about what Helm's DSSE envelopes are allowed to claim as their
`alg`, not a bug in one file.

## What happens without a ruling

`ui/lib/verify-parity-gate.test.mjs`'s `expected-divergence 1` test pins the
CURRENT behavior on both sides (hub rejects, ui accepts) and fails loudly if
either side's behavior silently changes — so the divergence stays visible
and gated instead of tolerated. It does not resolve the question; it only
prevents the question from going unnoticed until someone does.

## DETERMINATION (2026-07-25)

**`"EdDSA"` is the normative value. `"Ed25519"` is a nonconforming `alg`
string and must never be accepted.**

### Sources, cited

- **RFC 8037 §3.1** (JOSE, "CFRG Elliptic Curve Signatures"): registers the
  JOSE `alg` value **`"EdDSA"`** for signatures using edwards-curve keys; the
  curve itself (`Ed25519` or `Ed448`) is carried separately in the JWK's
  `crv` member, never in `alg`. `"Ed25519"` is not a value RFC 8037 defines
  or permits in `alg`.
- **IANA "JSON Web Signature and Encryption Algorithms" registry**: lists
  `EdDSA` (registered by RFC 8037); does not list `Ed25519` as an `alg`.
- **RFC 9053 (COSE, §8.2) / IANA "COSE Algorithms" registry**: mirrors the
  same split — COSE's Ed25519 signature algorithm identifier is also
  `EdDSA` (label `-8`), curve carried in the key's `crv` (`OKP`/`Ed25519`).
- **RFC 9964 ("ML-DSA for JOSE and COSE")**: registers per-parameter-set
  `alg` identifiers for ML-DSA (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`) —
  this is why Helm's ML-DSA-44 co-signature already correctly carries
  `alg: "ML-DSA-44"` on both sides, undisputed. RFC 9964 does **not** touch
  Ed25519/EdDSA naming; SPEC.md §26.2's sentence "Algorithm identifiers MUST
  be the RFC 9964 JOSE registrations" is imprecise (Ed25519's registration
  is RFC 8037, not 9964) but its *intent* — "use the actual JOSE alg-registry
  string" — is unambiguous and resolves to `EdDSA`, not `Ed25519`.
- **DSSE** (`secure-systems-lab/dsse`) does not define its own `alg`
  vocabulary; it defers to whatever the payload's signing convention uses,
  which for Helm is JOSE/COSE per the citations above. No "different field"
  possibility applies here — DSSE has exactly one `alg` slot per signature
  entry, and it is JOSE-registered.

**"Both, in different fields" does NOT apply** — there is no second field
where `Ed25519` would be the correct value. The curve name has no proper
home in this envelope shape at all; it's implied by the key, not asserted by
the signature entry.

### JOB 2 — which side changes

**Recommendation: tighten `ui/lib/verify-envelope.mjs` to `alg === "EdDSA"`
only** (drop the `|| s.alg === "Ed25519"` branch), matching
`hub/envelope.mjs` exactly.

- **Rejected: widen the hub to accept both.** Would make the hub accept a
  nonconforming value with no normative basis — widening a verifier's
  acceptance without a standards reason is the dangerous direction, not the
  safe one.
- **Rejected: normalize on read.** No producer conflict to reconcile; this
  isn't a legacy-format problem, it's one side accepting a value that was
  never valid.
- **Not structural.** The field itself is used correctly (right slot, right
  purpose) — only one side's accepted-value set is wrong.

**Compatibility cost: none found.**
- `hub/envelope.mjs` `emitEnvelope()` — the only real Ed25519 envelope
  producer in this repo — has always emitted `"EdDSA"` only (confirmed by
  reading the function; not a hypothesis).
- `dist/release-manifest.dsse.json`, the one real signed artifact checked
  into the repo, carries `"EdDSA"`.
- The only place `"Ed25519"` appears as an envelope `alg` value anywhere in
  the repo is `fixtures/envelope/golden.json` — a hand-authored fixture with
  placeholder signature bytes (`"MEUCIQDx3n8s0k1z...base64sig...=="`, not a
  real signature), used only to exercise `schema/envelope.schema.json` via
  `scripts/validate-schemas.mjs`. It is not exchanged with, or verified
  against, any real signer output.
- Tightening `ui` therefore rejects **zero** artifacts any real Helm
  producer has ever emitted.

### A second, related divergence found while sourcing this (flagging, not fixing)

`schema/envelope.schema.json` and `schema/countersignature_slot.schema.json`
both declare `"alg": { "enum": ["Ed25519", "ML-DSA-44"], "description":
"RFC 9964 JOSE algorithm identifier..." }` — the enum lists the WRONG value
under a description that correctly says "JOSE algorithm identifier."
`fixtures/envelope/golden.json` conforms to this (wrong) enum, which is why
`validate-schemas.mjs` (a real CI gate) currently passes it. **This is
latent, not live**: nothing wires `hub/envelope.mjs`'s real output through
these schemas today (`sea-source-manifest.mjs`'s reference to
`envelope.schema.json` is packaging-manifest only, not validation), and
`countersignature_slot.schema.json` is explicitly Phase-4/"NOT WIRED" per
its own title. But a fix row for the `ui` divergence should update both
schema enums (`"Ed25519"` → `"EdDSA"`) and `fixtures/envelope/golden.json`'s
`alg` value in the same change, or the schemas will keep certifying the
nonconforming string as correct.

### JOB 3 — the pinned gate entry a fix row must update

`ui/lib/verify-parity-gate.test.mjs`'s `expected-divergence 1` (pins
`hub.valid=false` / `ui.valid=true` on an `alg:"Ed25519"` envelope) is the
entry a fix row flips once `ui/lib/verify-envelope.mjs` is tightened —
`ui.valid` becomes `false` too and the vector moves from
expected-divergence to ordinary agreement. **Not touched by this row.**

### Lenient-vs-strict, on security grounds

Confirmed the dangerous direction is the one being closed: the browser
(lenient) is the side that changes, not the hub (strict) — this recommendation
narrows acceptance, it does not widen it. No `phil`-lens objection: there is
no legitimate producer this narrowing excludes.
