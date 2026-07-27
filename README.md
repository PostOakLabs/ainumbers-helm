# AINumbers Helm

Local-first control plane for verifiable connected workflows: a self-installed hub daemon (`helmd`) plus a static browser UI (`app.html`) that run deterministic OCG kernels against connector-retrieved data and emit independently verifiable, regulator-legible evidence bundles.

**Status:** Phase 1 foundation — pre-release, private.

- Build spec: `HELM-PHASE1-BUILD-SPEC.md` (workspace root, AINumbers estate)
- Normative profile: OCG SPEC.md §26 `ocg-control-plane@1` (draft: `SPEC-S26-CONTROL-PLANE-PROFILE-DRAFT.md`)

## Layout (target)

```
hub/       helmd daemon (TypeScript/Node, SEA binary)
ui/        app.html static surface
schema/    Control Plane profile JSON Schemas (SSOT)
fixtures/  golden + tampered fixtures per schema
scripts/   vendoring, CI, packaging, release signing
packaging/ winget/homebrew/npm manifest templates (HELM-H8)
docs/      install + operational docs
```

## Installing

See `docs/INSTALL.md` — winget/brew/npm, manual download + offline signature
verification, and how the version-check notice works (never an auto-updater).

OCG kernels and verify code are vendored pinned from `PostOakLabs/ainumbers` — never edited here; fix upstream and re-vendor.

## Contributing

Run `node scripts/setup-hooks.mjs` once per clone to enable the local pre-push shift-left gate (mirrors CI — see `docs/RELEASING.md`).

## Release channel

`docs/RELEASE-CHANNEL.md` — CalVer discipline, signed release notes, the
machine-readable version feed, and the support-floor signal, for orgs running
a CAB-lite process against upstream releases.

## Security

Loopback-only daemon, bearer-token pairing, Host/Origin validation, OS-keychain secret storage, default-deny egress. See `SECURITY.md` (HELM-0) for the disclosure contact.

## Trust

`docs/TRUST.md` — a complete enumeration of every outbound request the
shipped code can make, a reproducible zero-telemetry recipe you can run
yourself in under 10 minutes, the data-flow statement, where to find the CycloneDX SBOM published with every release,
zone-level DNS hardening status (DNSSEC + CAA, runbook in
`docs/DNSSEC-CAA-RUNBOOK.md`), dated SSL Labs / Mozilla Observatory grades
for every host we touch, and the SRI statement.

## Continuity

Evidence bundles self-verify independently of the vendor: every bundle
carries its own offline verifier (`ui/vendored/` + `ui/lib/standalone-verifier.mjs`),
so a bundle produced today stays checkable — hashes, signatures, the
RFC 3161 timestamp chain — with no call back to AINumbers, no daemon, no
subscription, even if this project stops.

## License and trademark

Apache License, Version 2.0 — see `LICENSE` and `NOTICE`. The license
covers the code; it grants no rights to the "Helm" name or logo — see
`docs/TRADEMARK.md` for what's allowed when redistributing or building on
Helm.
