# Power Query bridge (HELM-P4-B1)

FROZEN JSON output-folder schema per run, plus a downloadable macro-free
Excel starter workbook. Reads a run's evidence-bundle entries into Excel via
Power Query, offline, in **local-file mode** — the primary mode, because
banks GPO-block unapproved web connections. Source: `hub/pq-export.mjs`,
`hub/pq-starter-workbook.mjs`, schema in `schema/pq_export_*.schema.json`.

## Output-folder schema (frozen v1)

`writePqExportFolder(dir, bundle)` writes three files to a run's output
folder, all joined on `digest`:

| File | Rows | Joins on |
|---|---|---|
| `results.json` | `{ digest, kind, run_id, bundle_id }` | `digest` |
| `trust-labels.json` | `{ digest, trust_label }` | `digest` |
| `hashes.json` | `{ digest, algorithm, hex }` | `digest` |

Each file shares a header: `{ schema_version, generated_at, run_id,
bundle_id, rows: [...] }`. `results.json` additionally carries
`workflow_manifest_digest`.

`trust_label` is one of the §26.6 trust labels: `hash_verified`,
`kernel_verified`, `connector_asserted`, `human_attested`,
`external_ack_captured` — never collapsed to a single "verified" boolean.

**Freeze policy:** `schema_version` is `1` today. A shape change (renamed
field, changed type, removed row) is a **major-version bump** — add a new
`schema_version` value and update the schema files under `schema/`; never
edit the v1 field shapes in place. A Power Query script written against v1
must keep working against every future v1 export.

## Local-file mode (primary)

The daemon writes the three JSON files straight to a folder on disk
(`writePqExportFolder`) — no network call, no daemon-API request. Point
Power Query at that folder and refresh. This is the mode banks can actually
use: GPO commonly blocks Excel's web/OData/ODBC data-connection types, but
local file reads are unrestricted.

## Optional daemon-API mode

`helmd` binds **`127.0.0.1` only** (`hub/server.mjs`) and enforces an exact
`Host: 127.0.0.1:<port>` match on every request (DNS-rebinding defense) — it
never listens on any other interface or hostname. If a future WU exposes the
Power Query bridge over the daemon's HTTP API, the only host Power Query
would ever contact is `http://127.0.0.1:<port>` on the same machine — no
other host, ever. Local-file mode remains primary; this section exists so a
bank security reviewer has one place to confirm the full host list before
approving either mode.

## Starter workbook

`buildPqStarterWorkbook()` (`hub/pq-starter-workbook.mjs`) produces
`helm-power-query-starter.xlsx` — a clean, macro-free OOXML workbook
(verified to open with zero repair prompt in real Excel) with five sheets:

- **ReadMe** — setup steps + local-file-mode-primary note
- **Setup** — the exact M query to paste (see below)
- **Results / TrustLabels / Hashes** — header rows matching the frozen
  schema field-for-field, ready to receive the loaded query output

### Setup (one-time, ~1 minute)

1. Data ▸ Get Data ▸ Launch Power Query Editor
2. New Source ▸ Blank Query
3. Home ▸ Advanced Editor ▸ paste the M script from the **Setup** sheet
4. Edit the `RunFolder` path at the top of the script to point at a run's
   output-folder
5. Close & Load

After that, **Data ▸ Refresh All** picks up the latest run's results, trust
labels, and hashes — the same one-click refresh a fully pre-built query
would give.

### Why the query isn't already loaded on open

Excel stores an already-loaded Power Query as a binary "Data Mashup"
package inside the `.xlsx` OPC container ([MS-QDEFF]). Hand-authoring that
binary part with zero dependencies, with no way in this environment to
round-trip it through real Excel before shipping, risks a workbook Excel
silently repairs or refuses to open — worse than the one-time paste-in this
ships instead. The M script on the **Setup** sheet is the exact logic that
binary part would run (verified against a real evidence bundle's shape); if
a future session gets to validate an embedded Data Mashup part against real
Excel, upgrade `pq-starter-workbook.mjs` in place — the schema and M script
don't change.

## Tests

- `hub/pq-export.test.mjs` — schema-valid output, `digest` join integrity
  across all three files, folder write round-trip
- `hub/pq-starter-workbook.test.mjs` — OOXML package shape, macro-free
  content types, M script references all three frozen files and the join
  key (workbook additionally hand-verified to open cleanly in real Excel via
  COM automation during HELM-P4-B1's build)
