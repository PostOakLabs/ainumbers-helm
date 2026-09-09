# Agent-gateway action log → Helm evidence bundle (demo)

**Status:** worked example, not a shipped product feature. A standalone converter script plus fixture proving a specific claim, for use in partner conversations.

## What this demonstrates

Several agent-gateway products (the categories they fall in, no vendor named or implied) log agent actions in a proprietary/vendor-specific format: what an agent did, against what host, under what scope, at what time. That log is a **claim** ("this action happened"). None of these products let a third party verify the log **offline**, after the fact, without trusting the vendor's server.

This demo converts a **generic, vendor-neutral** JSON-lines action log into a **signed, hash-chained, offline-verifiable Helm evidence bundle**, using ONLY machinery Helm already ships:

- `hub/journal.mjs`: the append-only, per-stream running-hash journal (SPEC.md §26.5)
- `hub/checkpoint.mjs`: signed periodic checkpoints over journal state
- `hub/bundle.mjs`: the evidence bundle assembler and offline `verifyBundle()`
- `ui/lib/verify-bundle.mjs`: the same zero-network verifier `verify.html` embeds in the browser

**No new envelope member, no new object kind, no new schema.** Each action-log line is sealed as an existing `connector_attestation` object (`schema/objects/connector_attestation.schema.json`) with trust label `connector_asserted`, exactly the right epistemic claim: the gateway *asserted* the action happened; nothing here re-executes it (`kernel_verified`) or claims a human reviewed it (`human_attested`). See `schema/evidence_bundle_manifest.schema.json` §26.6 for the full trust-label vocabulary.

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

The converter (`scripts/gwlog-to-bundle.mjs`) reads only these fields. Extra vendor-specific fields on a line are ignored, not rejected, so a real export doesn't need to be stripped down first.

## Running it

```
node scripts/gwlog-to-bundle.mjs fixtures/agent-gateway-action-log.example.jsonl \
  --out bundle.json --keys-out publicKeys.json

node scripts/verify.mjs bundle.json --keys publicKeys.json
# result: VALID
```

Flip one byte in a sealed object's signature and re-verify, using the SAME verifier, with no special-cased tamper detector:

```
result: INVALID
reason: entry_envelope_invalid:sha256:...
```

`scripts/gwlog-to-bundle.test.mjs` runs both cases (golden valid, tampered invalid) as an automated RED-before-GREEN test; see `TAMPERED-BUNDLE` in that file.

## Mapping notes (factual only, no partnership implied)

The four gateway-shaped products/categories that motivated this demo (an agent runtime, an MCP tool registry, a browser/agent action recorder, and an integration-automation product) each log roughly the same shape: an actor, an action, a target, a timestamp, and some notion of scope or permission. The generic schema above is deliberately shaped to accept exactly that, factually. **This is a mapping observation, not an integration, partnership, or endorsement; none exists.** A real export from any of these would need a small field-rename shim ahead of this converter; none is included here because doing so by name would imply a relationship the product doesn't have.

## Importers (HELM-GWLOG-IMPORT-*)

Each importer row (spec: `HELM-MAINTENANCE-BUILD-SPEC.md` §3.2) gets a real source's JSON-lines to fit this generic shape via a shared field-map runner:

- `scripts/gwlog-import/_map.mjs`: the shared runner. Reads a source's JSON-lines, applies the source's field map (source path to generic field, with per-field transforms), and invokes `scripts/gwlog-to-bundle.mjs` unchanged. Digest/body policy: a source digest is passed through; a raw body is hashed (sha256) and DROPPED before anything is written; a line carrying neither a body nor a digest is refused with reason `no_digest`; a body-bearing line whose digest no longer matches `sha256(body)` is refused with reason `digest_mismatch`. Raw bodies never reach the bundle.
- `scripts/gwlog-import/agentgateway.mjs`: the agentgateway map. agentgateway (Rust, Agentic AI Foundation) logs a structured access log line for every request it proxies (HTTP, LLM, MCP). See `agentgateway.dev/docs/.../documentation/observability/access-logs/view/` and the CEL reference (`agentgateway.dev/docs/standalone/main/reference/cel/cel-context/`) for the exact field names the map uses (`http.method/http.host/http.path`, `request.startTime`, `mcp.sessionId`, `mcp.methodName`, operator-added `user_id` via the documented `accessLog.add` CEL hook). Fields those pages do not document (JSON-format timestamp key, agent/tool version, a user field beyond `user_id`) map to `"unknown"`, and the module header says so. `request_digest`/`response_digest` are the enrichment field names this map expects from the documented `accessLog.add` hook when an export wants digests rather than bodies.

## Option named, not taken

The scan that motivated this row also surfaced the option of **upstreaming a converter or format doc to the `agentgateway` open-source project** (a CNCF sandbox project, MIT-licensed egress/ingress gateway for agent traffic) so this mapping ships from their side too. **That decision belongs to the product owner, not this demo.** This demo contacts nobody and opens no external PRs. Flagging it here so it isn't lost.
