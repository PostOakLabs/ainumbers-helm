# HELM-MCPB-1 — Pins and structural decisions for the `.mcpb` bundle

This file records the external pins and the judgment calls behind
`packaging/mcpb/manifest.json` + `scripts/build-mcpb.mjs` (spec:
`HELM-MAINTENANCE-BUILD-SPEC.md` §3.5).

## mcp-remote pin

| Field | Value |
|---|---|
| Package | [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) (MIT, `punkpeye/mcp-remote`) |
| Pinned version | `0.8.6` |
| npm tarball | `https://registry.npmjs.org/mcp-remote/-/mcp-remote-0.8.6.tgz` |
| npm `dist.integrity` (SRI) | `sha512-23MuEy84alflR7cGoKmONqE6Xny9UlvucxRCPV0NFWz4mQarf77HTWtiaHQ4XzypKya6JdPGwCDy/kZVi5L96w==` |
| Tarball sha512 (hex, computed from the downloaded tarball at claim 2026-09-10) | `db732e132f386a57e547b706a0a98e36a13a5e7cbd525bee7314423d5d0d156cf89906ab7fbec74d6b626874385f3ca92b26ba25d3c6c020f2fe46558b92fdeb` |
| `dist.shasum` (sha1) | `b0d53af611c2b9fb48ab228838134cd60068e5e0` |

The SRI above and the computed hex sha512 are the same digest (verified at
claim: base64-decoding the registry SRI equals the hex sha512 of the
downloaded tarball, byte-for-byte). `0.8.6` was the registry `latest` tag at
claim (2026-09-10) and matches `agent-kit/kit.json` → `mcpRemote.pin`
(claimed 2026-09-09 by HELM-AGENT-KIT-1) — `scripts/build-mcpb.mjs` enforces
that agreement at build time; the manifest is never allowed to drift from
kit.json.

mcp-remote is a **user-side tool helm merely documents** (spec §1): the host
(Claude Desktop / Cowork) downloads and runs it via `npx`; it is never
bundled or vendored by helm. Its README documents the `--header` flag used
by the manifest, e.g. the args pair:

```
"--header",
"Authorization: Bearer ${AUTH_TOKEN}"
```

(the manifest uses the mcpb `${user_config.token}` interpolation in place of
`${AUTH_TOKEN}`).

## Vendored manifest schema

| Field | Value |
|---|---|
| Upstream | [modelcontextprotocol/mcpb](https://github.com/modelcontextprotocol/mcpb) |
| Pinned commit | `70fe3b34cd6dff1b3bba046638edc72a6467a4fb` |
| Vendored file | `hub/vendored/mcpb-schema/mcpb-manifest-v0.3.schema.json` (Draft 07, `manifest_version` 0.3; byte-identical to `schemas/mcpb-manifest-latest.schema.json` at the pin — sha256 `3a0ac9d845711a1b9b17dfa5a52f8b60628239d6a86a9db417206a9efc78592d` for both) |
| License | Hybrid upstream LICENSE (Apache-2.0 / MIT / CC-BY-4.0), carried in-tree; upstream ships no NOTICE file (checked 2026-09-10) |

Recorded in `VENDORED.md`; integrity verified by `scripts/verify-vendored.mjs`.

## Structural decisions (documented, not silent)

1. **`server.entry_point` is `"npx"`.** The MCPB schema (0.3) requires
   `server.entry_point`, but this bundle deliberately ships **no server
   file** — the row's contract is "no hand-written shim": the bridge is
   `mcp-remote`, fetched by the host's own `npx -y mcp-remote@<pin>`.
   Hosts launch the bundle via `server.mcp_config.command`/`args` and do not
   execute `entry_point` when `mcp_config` is present, so the field is inert
   at runtime; it names the process the host actually manages (`npx`).
   Consequence, stated plainly: Anthropic's optional maintainer CLI
   (`@anthropic-ai/mcpb validate`) would flag `entry_point` because it
   expects a bundled file to exist on disk. That CLI is a maintainer-side
   convenience, **not** a gate of this row — the gate is the vendored schema
   validation in `scripts/build-mcpb.mjs` + its test.
2. **`icon.png` is generated, not designed.** The repo carries no image
   asset to reuse (checked: no PNG/ICO/SVG anywhere in the repo at claim),
   so `scripts/build-mcpb.mjs` emits a deterministic 64x64 PNG (deep-water
   blue `#0B3B5C` with an amber `#F0B232` inset block) using a stored
   deflate block — no compressor in the loop, byte-stable everywhere. A
   designed brand icon can replace it later (e.g. under
   HELM-PACKAGING-RETIRE-1) by swapping the generator's source.
3. **`manifest.version` is injected at build time** from `package.json` —
   one source of truth for the release version; the copy in the source
   manifest is informational-at-rest and never shipped (the zip carries the
   derived manifest).
4. **The `version` in `dist/helm-<version>.mcpb`** is the `package.json`
   version (`2026.9.3` at claim); the file lands in `dist/`, which is
   git-ignored — the bundle is built locally (and later by the release
   pipeline, HELM-PACKAGING-RETIRE-1), never committed.
