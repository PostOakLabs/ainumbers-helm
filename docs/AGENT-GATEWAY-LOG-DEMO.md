# Agent-gateway action log → Helm evidence bundle (demo)

**Board row:** `GWLOG-DEMO-1`. **Status:** worked example, not a shipped product feature — a standalone converter script + fixture proving a specific claim, for use in partner conversations.

## What this demonstrates

Several agent-gateway products (the categories they fall in, no vendor named or implied) log agent actions in a proprietary/vendor-specific format: what an agent did, against what host, under what scope, at what time. That log is a **claim** ("this action happened") — none of these products let a third party verify the log **offline**, after the fact, without trusting the vendor's server.

This demo converts a **generic, vendor-neutral** JSON-lines action log into a **signed, hash-chained, offline-verifiable Helm evidence bundle**, using ONLY machinery Helm already ships:

- `hub/journal.mjs` — the append-only, per-stream running-hash journal (SPEC.md §26.5)
- `hub/checkpoint.mjs` — signed periodic checkpoints over journal state
- `hub/bundle.mjs` — the evidence bundle assembler + offline `verifyBundle()`
- `ui/lib/verify-bundle.mjs` — the same zero-network verifier `verify.html` embeds in the browser

**No new envelope member, no new object kind, no new schema.** Each action-log line is sealed as an existing `connector_attestation` object (`schema/objects/connector_attestation.schema.json`) with trust label `connector_asserted` — which is exactly the right epistemic claim: the gateway *asserted* the action happened; nothing here re-executes it (`kernel_verified`) or claims a human reviewed it (`human_attested`). See `schema/evidence_bundle_manifest.schema.json` §26.6 for the full trust-label vocabulary.

## The generic input schema

One JSON object per line (`fixtures/agent-gateway-action-log.example.jsonl`), vendor-neutral field names:

| field | meaning | required |
|---|---|---|
| `ts` | ISO-8601 instant the action executed | yes |
| `run_id` | logical run/session grouping id | yes |
| `actor_id` | id of the acting agent/tool (vendor's own id, passed through unchanged) | yes |
| `actor_version` | agent/tool version string, `"unknown"` if untracked | yes |
| `action` | operation name, e.g. `"tool.invoke"`, `"http.get"` | yes |
| `target_host` | host/service acted upon | yes |
| `scope` | array of permission scopes granted for the action | yes |
| `request_digest` | `sha256:<hex>` digest of the request payload (**never** the raw payload) | yes |
| `response_digest` | `sha256:<hex>` digest of the response payload (**never** the raw payload) | yes |
| `classification` | data classification tag, e.g. `"internal"`/`"public"` | yes |

The converter (`scripts/gwlog-to-bundle.mjs`) reads only these fields — extra vendor-specific fields on a line are ignored, not rejected, so a real export doesn't need to be stripped down first.

## Running it

```
node scripts/gwlog-to-bundle.mjs fixtures/agent-gateway-action-log.example.jsonl \
  --out bundle.json --keys-out publicKeys.json

node scripts/verify.mjs bundle.json --keys publicKeys.json
# result: VALID
```

Flip one byte in a sealed object's signature and re-verify — the SAME verifier, no special-cased tamper detector:

```
result: INVALID
reason: entry_envelope_invalid:sha256:...
```

`scripts/gwlog-to-bundle.test.mjs` runs both cases (golden valid, tampered invalid) as an automated RED-before-GREEN test — see `TAMPERED-BUNDLE` in that file.

## Mapping notes (factual only — no partnership implied)

The four gateway-shaped products/categories that motivated this demo (an agent runtime, an MCP tool registry, a browser/agent action recorder, and an integration-automation product) each log roughly: an actor, an action, a target, a timestamp, and some notion of scope or permission — the generic schema above is deliberately shaped to accept exactly that, factually. **This is a mapping observation, not an integration, partnership, or endorsement — none exists.** A real export from any of these would need a small field-rename shim ahead of this converter; none is included here because doing so by name would imply a relationship the product doesn't have.

## Option named, not taken

The scan that motivated this row also surfaced the option of **upstreaming a converter or format doc to the `agentgateway` open-source project** (a CNCF sandbox project, MIT-licensed egress/ingress gateway for agent traffic) so this mapping ships from their side too. **That is Tim's call, not this row's** — this row contacts nobody and opens no external PRs. Flagging it here so it isn't lost.
