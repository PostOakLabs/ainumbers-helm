# Company-profile config URL (HELM-P4-J1)

An embedder (systems integrator, internal IT team, consultancy) can restyle
and retemplate the Helm UI without a fork or a build step: host a static JSON
file anywhere over https and point the app at it once.

## Usage

```
https://127.0.0.1:4173/#/choose?config=https://your-host.example/helm-profile.json
```

Wait — `config` is a **query** parameter (`?config=`), not a hash param, so it
survives alongside the app's own `#/view` routing:

```
http://127.0.0.1:4173/?config=https%3A%2F%2Fyour-host.example%2Fhelm-profile.json#/choose
```

The URL is validated (`https://` only), fetched, schema-checked, and — on
success — saved as a per-browser setting (`localStorage`). Every later visit,
including the ones opened by `helmd open` (which never carries a query
string), reapplies the same profile without the link. Loading a different
`?config=` URL overwrites the saved setting; there's no UI to clear it today
short of clearing site data.

## Config shape

See `schema/company_profile.schema.json`. Every field is optional except
`schema_version` (currently always `1`) and `profile_name`:

- `templates` — slugs to feature on Choose, in order. A profile can only
  narrow/reorder the daemon's own `/templates` list, never invent entries
  that don't exist there.
- `branding` — CSS custom-property overrides (e.g. `--accent`, `--surface` —
  see `ui/theme.css` for the full token set) applied to `:root` via
  `style.setProperty`. Keys not matching `^--[a-z][a-z0-9-]*$` are silently
  dropped, never turned into a stylesheet rule.
- `relay_url` — overrides the default anchor relay base
  (`https://anchor.ainumbers.co`) that browser-mode anchoring
  (`ui/lib/anchor-browser.mjs`) posts DER TimeStampReq bytes to. The relay
  stays untrusted regardless of which one answers — the returned token's
  messageImprint is still checked against the requested hash before it's
  ever called an anchor.
- `pinned_kernel_versions` — `kernel_id -> semver` map, informational/display
  only in this WU. No enforcement engine reads it yet.

## Failure mode

Unreachable host, non-200, non-JSON body, or a shape that fails schema
validation all just skip application and leave the app on defaults — no
blocked render, no thrown error, a `console.warn` only. A failed fetch never
overwrites a previously-saved-good config URL.

## CSP implication

The daemon-served shell's CSP (`hub/static.mjs`) widens `connect-src` from
`'self'` to `'self' https:` to allow this fetch — `script-src`, `style-src`,
and `img-src` are unchanged, so a hostile config can only ever be read as
JSON data, never loaded as executable content, a stylesheet, or a
navigation target. Config is data, never code, by construction: nothing in
the loader `eval`s a value, builds HTML by concatenation, or treats a config
field as a script/URL to load.

## Config is data, never code

There is no field the app interprets as JavaScript, a `<script src>`, or an
HTML fragment. Branding values only ever reach `style.setProperty`; the
template list only ever filters an existing array by string equality; the
relay URL and kernel-version map are read as plain strings.
