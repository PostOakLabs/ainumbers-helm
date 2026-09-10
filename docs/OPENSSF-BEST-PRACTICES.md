# OpenSSF Best Practices: prepared self-certification answers

This file records Helm's answers to the OpenSSF Best Practices badge
questionnaire (https://bestpractices.dev), section by section, with the
in-repo evidence for each answer. Submitting the questionnaire requires a
human project account, so the answers live here first: anyone can check
them against the repository, and the maintainer submits them as-is.

Status values: MET (answer is yes, with evidence), PARTIAL (answer is
partially yes; the gap is stated), NO (not claimed).

## Basics

- Public source repository: MET. https://github.com/PostOakLabs/ainumbers-helm
  is a public git repository holding all source, schemas, fixtures, tests,
  and CI configuration.
- License: MET. Apache License 2.0, stated in `LICENSE` at the repo root,
  with `NOTICE` and `THIRD_PARTY_NOTICES.md` for third-party attributions.
- Project site: MET. https://ainumbers.co plus the repository itself; both
  served over HTTPS.
- Documentation: MET. `docs/INSTALL.md` covers installation and offline
  signature verification; `README.md` covers layout and release channel;
  `docs/TRUST.md` documents every outbound network call the software can
  make; `docs/RELEASING.md` documents the release pipeline.
- Documentation in English: MET. All user-facing and developer docs are in
  English.
- Effort: MET. The project ships a daemon (`helmd`), a browser UI, a JSON
  Schema profile, vendored deterministic kernels, packaging manifests, and
  a signed release pipeline.

## Change Control

- Version control: MET. Git, with the full public commit history on GitHub;
  any previous version can be checked out and inspected.
- Unique version identifiers: MET. Calendar versions (for example 2026.9.10)
  with every release tagged in git and described in a machine-readable
  version feed (`docs/RELEASE-CHANNEL.md`).
- Release notes: MET. Release notes are produced and signed per release
  (`docs/RELEASE-CHANNEL.md`).
- Contribution process: MET. Changes arrive as GitHub pull requests. The
  `Contributing` section of `README.md` and `docs/RELEASING.md` document
  the gates every change must pass, which are enforced by a pre-push hook
  and mirrored in CI.
- Code review: PARTIAL. Pull requests carry CI gate runs before merge, but
  this is a small-maintainer project, so a two-person review of every
  change is not claimed.

## Reporting

- Vulnerability reporting process: MET. `SECURITY.md` asks reporters to use
  private channels only (GitHub Security Advisories or email to
  security@postoaklabs.com) and names the disclosure contact.
- Response handling: PARTIAL. The policy commits to reading and answering
  every report; a response-time commitment is explicitly not made, and the
  policy says so.
- Public disclosure: MET. Confirmed vulnerabilities are published as GitHub
  Security Advisories on this repository once fixed.

## Quality

- Build from source: MET. The project builds with Node.js built-ins alone.
  Zero npm runtime dependencies are a policy enforced by a test
  (`bin/zero-dep.test.mjs`), so no dependency install step exists.
- Automated test suite: MET. Roughly 150 `*.test.mjs` files cover the
  daemon, the UI library, schemas (golden and tampered fixtures per
  schema), gateway-log tooling, and release tooling. Run with
  `node scripts/test.mjs` (or `node --test`).
- Test suite invocation documented: MET. The run command appears in
  `docs/RELEASING.md`, `README.md`, and the CI workflow itself.
- Continuous integration: MET. `.github/workflows/ci.yml` runs on every
  push to main and every pull request. The blocking CI job runs the same
  gate list as the local pre-push hook, and
  `scripts/check-hook-ci-parity.mjs` fails CI if that parity drifts.
- Test coverage of major branches: PARTIAL. The suite exercises the daemon
  end to end on loopback, verifies schemas against golden and tampered
  fixtures, and covers release and vendoring tooling. Line-coverage tooling
  is not used, in keeping with the zero-dependency policy.
- Coding standards: PARTIAL. Standards are enforced mechanically where they
  matter: `scripts/lint.mjs` syntax-checks every module, schemas are
  validated in CI, and bespoke gates block internal-jargon leaks and
  documentation drift. No written style guide is published.
- Release artifacts: MET. Every release ships SHA256SUMS, SSHSIG signatures
  (offline-verifiable with the shipped `allowed_signers`), GitHub build
  provenance from `actions/attest-build-provenance`, and a CycloneDX SBOM
  generated in CI (`docs/TRUST.md` section 4, `docs/RELEASING.md`).

## Security

- Secure transport: MET. Every project-controlled host is served over TLS;
  the DNS zones carry DNSSEC and CAA records, with dated SSL Labs grades
  per host in `docs/TRUST.md`.
- Cryptographic practice: MET. Signatures use Ed25519 via SSHSIG
  (`hub/extsig.mjs`), timestamps use RFC 3161, and evidence bundles carry a
  dual signature envelope that pairs the Ed25519 signature with a
  post-quantum ML-DSA signature. Algorithms are named and pinned in the
  shipped code and tests.
- Signed releases: MET. See release artifacts under Quality; verification
  instructions are in `docs/RELEASING.md` and `docs/INSTALL.md`.
- Dependency policy: MET. Zero runtime npm dependencies, enforced by a
  test. Third-party code enters only as pinned, license-listed vendored
  copies under a `VENDORED.md` + LICENSE pair (`scripts/vendor.mjs` is the
  single re-vendoring path).
- CI supply-chain hygiene: MET. Every GitHub Action in every workflow is
  pinned by full commit SHA, and Dependabot (`.github/dependabot.yml`)
  watches the github-actions ecosystem for pin updates. The Scorecard
  workflow (`.github/workflows/scorecard.yml`) publishes the OpenSSF
  Scorecard result weekly with results publishing enabled and CI-scoped
  permissions.
- Static analysis: PARTIAL. CI runs `node --check` over every module,
  schema validation, and bespoke gates (hook-CI parity, internal-language
  leak, documentation hallmarks). No third-party static analyzer is wired
  in.
- Dynamic analysis: PARTIAL. The test suite exercises the daemon and the
  standalone verifier end to end on loopback; fuzzing is not used.

## Re-verification

Every claim above points at a file in this repository or a URL. The
quick checks: run `node scripts/test.mjs` (suite), `node
bin/zero-dep.test.mjs` (zero-dependency policy), and compare a release's
`SHA256SUMS` against the assets with the SSHSIG verification steps in
`docs/RELEASING.md`.
