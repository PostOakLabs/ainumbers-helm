// Single config file: ~/.helm/config.json. Created with defaults on first run.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { statePath } from "./state-dir.mjs";

const DEFAULTS = {
  port: 4173,
  // helm.html is a static, zero-backend page opened via file:// — browsers send
  // the literal string "null" as Origin for fetches from file:// documents.
  // Exact-match this (never a wildcard) per D8. Override for a served-UI deployment.
  allowedOrigin: "null",
  // D10: passive notice only, never an auto-updater. Empty string disables
  // the check entirely (airgapped installs).
  versionCheckUrl: "https://ainumbers.co/helm/version.json",
};

export function loadConfig() {
  const path = statePath("config.json");
  if (!existsSync(path)) {
    writeFileSync(path, JSON.stringify(DEFAULTS, null, 2) + "\n", { mode: 0o600 });
    return { ...DEFAULTS, path };
  }
  const parsed = JSON.parse(readFileSync(path, "utf8"));
  return { ...DEFAULTS, ...parsed, path };
}
