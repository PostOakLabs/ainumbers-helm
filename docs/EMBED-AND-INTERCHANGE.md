# Embed + interchange (HELM-P4-B3)

Two independent statics: an iframe embed recipe for SharePoint/Teams, and a
BPMN 2.0 XML export of workflow manifests for opening in a third-party BPMN
tool. Neither changes daemon behavior — both are docs/CLI additions.

## SharePoint/Teams embed recipe

Helm's UI (`ui/helm.html`) is a static page served by `helmd` over
`http://127.0.0.1:<port>` (see [OPERATIONS.md](OPERATIONS.md)). SharePoint
and Teams can embed any page reachable by URL inside an iframe web part —
but **the site does not default-allow being framed**. There is no
`X-Frame-Options`/`Content-Security-Policy: frame-ancestors` header sent by
`helmd` today because the daemon binds to loopback only; embedding requires
the embedder's tab to reach that same loopback origin, which SharePoint
(a remote origin) cannot do directly. Two supported paths:

### Path 1 — self-host (recommended, no vendor exposure)

Run `helmd` on a machine reachable from the embedding tab (a shared
workstation, an internal server) and embed that machine's loopback-bound
port via SharePoint's **Embed** web part:

```html
<iframe src="http://<host>:<port>/#token=<TOKEN>"
        width="100%" height="800" style="border:0"></iframe>
```

Requirements:
- `helmd` must be started with `--host 0.0.0.0` (or the host's LAN IP) —
  see `hub/server.mjs` bind options in [OPERATIONS.md](OPERATIONS.md).
  Binding beyond loopback widens the daemon's attack surface; only do this
  on a trusted internal network, never on a machine with a public IP.
- The `#token=` fragment carries the same auth token normal browser access
  uses (see [INSTALL.md](INSTALL.md)) — a fragment, not a query string, so
  it never reaches the SharePoint server or any proxy log.
- **Admin allowlist:** SharePoint/Teams tenant admins can restrict which
  external domains may be framed via the tenant's
  **Embed** setting (`SPO Management Shell` →
  `Set-SPOTenant -DisableCustomAppAuthentication $false` is unrelated; the
  relevant control is the **Content Security Policy / frame-ancestors
  allowlist** under *SharePoint admin center → Policies → Custom Script* or,
  for the newer **Viva Connections dashboard embed**, the app catalog entry
  for the iframe web part). Add the exact `http(s)://<host>:<port>` origin
  used above. Ask the tenant admin — this is an org-wide, security-relevant
  setting Helm cannot toggle from the client side.

### Path 2 — Teams tab (App Studio manifest)

For a persistent Teams tab rather than an ad-hoc iframe:

1. Register a Teams app manifest (`manifest.json`) with a `staticTabs` entry
   pointing `contentUrl` at the same `http://<host>:<port>/#token=<TOKEN>`
   URL as above.
2. Add `<host>:<port>` to `validDomains` in the manifest — Teams refuses to
   frame a domain not explicitly listed there, regardless of tenant policy.
3. Sideload or submit the app through Teams admin center; the same
   self-host requirement (Path 1) applies underneath.

Helm ships no manifest template for this — it's a thin wrapper around the
same URL, and the exact fields (app ID, icons) are tenant-specific enough
that hand-authoring per deployment is simpler than maintaining a stale
generator here.

### What Helm will not do

Helm will not send permissive `frame-ancestors: *` or omit frame protection
by default — that would let *any* page frame a running daemon and phish a
user's session token. Framing is opt-in, host-controlled, and requires the
admin-allowlist step above; this is a deliberate default, not a gap to
"fix."

## BPMN 2.0 XML export

`hub/bpmn-export.mjs` (`exportBpmn(manifest)`) maps a compiled pack's
`workflow-manifest.schema.json` document onto BPMN 2.0 XML — a diagram a
reviewer can open in **Camunda Modeler**, **Bizagi Modeler**, or
**Signavio** without running Helm at all. CLI:

```bash
node scripts/export-bpmn.mjs <workflow_id> out.bpmn
```

(or `npm run export:bpmn -- <workflow_id> out.bpmn`)

### Mapping (frozen — spec change = new mapping version)

| Manifest element | BPMN element |
|---|---|
| `trigger` | `startEvent` (`timerEventDefinition` if `type: "schedule"`) |
| `connector_inputs[]` | `serviceTask`, one per connector-fetch step |
| `nodes[]` (compute) | `serviceTask`, one per kernel node |
| `gates[]` | `exclusiveGateway` |
| `actions[]` | `serviceTask` (terminal); `target_host` recorded in `documentation`) |
| *(implicit)* | synthesized `endEvent` |

Sequence flows form **one straight-line chain** in manifest array order:
start → connector inputs → nodes → gates → actions → end. This is a
deliberate simplification: `workflow-manifest.schema.json` has no edge list
(nodes wire by `node_id`/`target_param`, not by predecessor pointers), so a
linear lane is the only rendering that doesn't invent structure the
manifest doesn't actually carry. Fields with no BPMN equivalent
(`kernel_digest`, `contract_digest`, `vault_ref`) are preserved as
`<bpmn:documentation>` text on the corresponding element so nothing is
silently dropped — but the XML is **not round-trippable**: re-importing it
into Helm is out of scope (unlike `hub/workflow-export.mjs`'s `.helm.json`,
which is a genuine round-trip format).

### Validating the output

The exported XML conforms to the BPMN 2.0 `bpmn:definitions`/`bpmn:process`
element set (executable-model-free — `isExecutable="false"`, since Helm's
own kernels are the actual execution engine, not a BPMN runtime). Confirm
by opening the file in any BPMN 2.0 tool's import dialog:

- **bpmn-js** (the library behind Camunda Modeler and the
  [bpmn.io demo](https://demo.bpmn.io)) — drag-and-drop the `.bpmn` file;
  it renders the straight-line lane with each element's name and, on
  hover/selection, its documentation text.
- **Camunda Modeler** (desktop) — File → Open, same result.
- **Bizagi Modeler** / **Signavio** — both import standard BPMN 2.0 XML via
  their respective import menus.

`hub/bpmn-export.test.mjs` covers structural well-formedness (balanced
tags, no dangling `sourceRef`/`targetRef`, XML-escaping of special
characters) as the offline gate; opening in an actual modeler is the
one-time manual confirmation this WU's `done:` line refers to.
