// Single config file: ~/.helm/config.json. Created with defaults on first run.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { statePath } from "./state-dir.mjs";

const DEFAULT_PORT = 4173;
// D10: passive notice only, never an auto-updater. Empty string disables
// the check entirely (airgapped installs).
const DEFAULT_VERSION_CHECK_URL = "https://ainumbers.co/helm/version.json";

// helmd serves the UI itself (HELM-U4, Syncthing pattern) — the page's real
// Origin is http://127.0.0.1:<port>, so that's what gets exact-matched
// (never a wildcard) per D8. Derived from `port`, not hardcoded, so a
// port-only override in config.json still gets a correct default.
function defaultOrigin(port) {
  return `http://127.0.0.1:${port}`;
}

export function loadConfig() {
  const path = statePath("config.json");
  if (!existsSync(path)) {
    const config = { port: DEFAULT_PORT, allowedOrigin: defaultOrigin(DEFAULT_PORT), versionCheckUrl: DEFAULT_VERSION_CHECK_URL };
    writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
    return { ...config, path };
  }
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  const port = parsed.port ?? DEFAULT_PORT;
  return {
    port,
    allowedOrigin: parsed.allowedOrigin ?? defaultOrigin(port),
    versionCheckUrl: parsed.versionCheckUrl ?? DEFAULT_VERSION_CHECK_URL,
    path,
  };
}
