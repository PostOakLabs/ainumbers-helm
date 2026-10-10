// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// helm record canonicalization v1, frozen: JavaScript enumeration order for
// array-index names and pre-911cfe38 `__proto__` handling; stored, hash-chained
// helm records depend on it; never "upgrade" it.
//
// This module is deliberately SELF-CONTAINED — it must not import the vendored
// `cgCanon` from ./vendored/ocg/kernels/_hash.mjs, because that vendored copy
// changes on every re-vendor (site commit 911cfe38 changed it, and the vendored
// tree now also carries `jcsStringify`, the RFC 8785 serializer whose output
// differs from v1 exactly for array-index member names and literal `__proto__`
// members). helm's OWN persisted records — journals, checkpoints, HA records,
// matter stores, snapshots — were hashed with the PRE-911cfe38 canonicalizer,
// so their digests only recompute byte-identically with the exact same code.
//
// The two deliberate v1 behaviors (both observable, both pinned by
// hub/record-canon-v1.test.mjs):
//   1. Array-index member names: v1 round-trips through an intermediate object,
//      so JSON.stringify's own-property enumeration order applies — integer-like
//      keys are enumerated in numeric order first. `{"9":1,"10":2}` therefore
//      serializes as `{"9":1,"10":2}`, NOT RFC 8785's `{"10":2,"9":1}`.
//   2. A member literally named `__proto__`: with a plain `{}` accumulator the
//      sorted assignment `o["__proto__"] = v` sets the PROTOTYPE, so the key and
//      its whole subtree silently vanish from the preimage. That silence is part
//      of the frozen v1 byte format — `{"__proto__":{...},"a":2}` hashes as
//      `{"a":2}`.
//
// Artifacts produced by the OCG site or the Worker (attested artifacts,
// connector contracts, kernel execution hashes) are NOT v1 — those verify
// through the vendored RFC 8785 path (`jcsStringify`), with a v1 retry and a
// distinct verdict where an external record may predate the change. See
// attested-artifact-runner.mjs and connector.mjs. Stored helm data is never
// migrated or rewritten.
//
// The canonicalizer body below is a byte-for-byte copy of the pre-911cfe38
// `cgCanon` from the vendored tree as pinned at site 0914b432
// (2026-09-24), composed with JSON.stringify — exactly the composition the
// hub record-hash helpers used before this module existed.

const cgCanonV1 = (v) =>
  Array.isArray(v) ? v.map(cgCanonV1)
  : (v && typeof v === 'object')
    ? Object.keys(v).sort().reduce((o, k) => (o[k] = cgCanonV1(v[k]), o), {})
    : v;

// The exact UTF-8 string every helm record digest is taken over.
export function recordCanonV1(x) {
  return JSON.stringify(cgCanonV1(x));
}
