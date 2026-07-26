# The `alg` question — `'EdDSA'` vs `'Ed25519'` — UNRESOLVED, needs a spec ruling

**Status: written up alongside the hub↔browser verifier parity gate. NOT
resolved here. Do not pick a winner without a spec ruling.**

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
