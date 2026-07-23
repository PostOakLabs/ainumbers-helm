# AINumbers Helm

Local-first control plane for verifiable connected workflows: a customer-installed hub daemon (`helmd`) plus a static browser UI (`helm.html`) that run deterministic OCG kernels against connector-retrieved data and emit independently verifiable, regulator-legible evidence bundles.

**Status:** Phase 1 foundation — pre-release, private.

- Build spec: `HELM-PHASE1-BUILD-SPEC.md` (workspace root, AINumbers estate)
- Normative profile: OCG SPEC.md §26 `ocg-control-plane@1` (draft: `SPEC-S26-CONTROL-PLANE-PROFILE-DRAFT.md`)

## Layout (target)

```
hub/       helmd daemon (TypeScript/Node, SEA binary)
ui/        helm.html static surface
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

## Security

Loopback-only daemon, bearer-token pairing, Host/Origin validation, OS-keychain secret storage, default-deny egress. See `SECURITY.md` (HELM-0) for the disclosure contact.
