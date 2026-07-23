// Shared state-dir resolution: ~/.helm by default, override via HELM_HOME for tests.
import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";

export function stateDir() {
  const dir = process.env.HELM_HOME || join(homedir(), ".helm");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export function statePath(...segments) {
  return join(stateDir(), ...segments);
}
