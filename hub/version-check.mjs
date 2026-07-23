// Version-check notice (HELM-H8, D10/D12): polls a static JSON endpoint and
// surfaces a passive "an update exists" notice. NEVER downloads or applies
// anything — D10 explicitly rules out an in-process auto-updater in Phase 1.
// Network failures (offline install, airgapped customer) are NOT errors:
// this check degrades to "unknown" silently, never blocks doctor or startup.
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { validate } from "../scripts/lib/schema-validator.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = JSON.parse(readFileSync(join(HERE, "..", "schema", "version_notice.schema.json"), "utf8"));

export const DEFAULT_VERSION_CHECK_URL = "https://ainumbers.co/helm/version.json";

function parseVersion(v) {
  const [core] = v.split("-");
  return core.split(".").map(Number);
}

// Returns -1/0/1 like a comparator: a<b / a==b / a>b.
export function compareVersions(a, b) {
  const [aM, am, ap] = parseVersion(a);
  const [bM, bm, bp] = parseVersion(b);
  if (aM !== bM) return aM < bM ? -1 : 1;
  if (am !== bm) return am < bm ? -1 : 1;
  if (ap !== bp) return ap < bp ? -1 : 1;
  return 0;
}

export async function checkVersion({ currentVersion, url = DEFAULT_VERSION_CHECK_URL, timeoutMs = 3000, fetchImpl = fetch } = {}) {
  let response;
  try {
    response = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    return { checked: false, reason: `unreachable: ${err.message}` };
  }
  if (!response.ok) {
    return { checked: false, reason: `http ${response.status}` };
  }

  let notice;
  try {
    notice = await response.json();
  } catch (err) {
    return { checked: false, reason: `invalid json: ${err.message}` };
  }

  const errs = validate(SCHEMA, notice);
  if (errs.length > 0) {
    return { checked: false, reason: "response failed schema validation", errs };
  }

  return {
    checked: true,
    currentVersion,
    latestVersion: notice.latest_version,
    minimumSupportedVersion: notice.minimum_supported_version,
    upToDate: compareVersions(currentVersion, notice.latest_version) >= 0,
    belowMinimumSupported: compareVersions(currentVersion, notice.minimum_supported_version) < 0,
    notice: notice.notice,
    releaseUrl: notice.release_url,
  };
}
