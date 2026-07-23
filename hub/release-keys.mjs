// Release signing keypair (HELM-H8, D10). Distinct from the per-install
// daemon keypair in keys.mjs: this key signs release manifests at build
// time in CI, not per-customer at runtime. Provisioned via the
// HELM_RELEASE_SIGNING_KEY_B64 env var (base64 of the same serializeKeys()
// JSON shape keys.mjs uses) — a GitHub Actions repo secret, never committed.
// The matching PUBLIC half is committed at schema/release-signing-keys.json
// so verify-release-manifest.mjs and installers can verify offline without
// trusting the network at verify time.
import { createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { deserializeKeys } from "./keys.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PUBLIC_KEYS_PATH = join(HERE, "..", "schema", "release-signing-keys.json");

export function loadReleaseKeysFromEnv(env = process.env) {
  const b64 = env.HELM_RELEASE_SIGNING_KEY_B64;
  if (!b64) {
    throw new Error("HELM_RELEASE_SIGNING_KEY_B64 not set — cannot sign a release manifest");
  }
  const obj = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  return deserializeKeys(obj);
}

// Public keys as committed in schema/release-signing-keys.json — safe to
// ship, used by verify-release-manifest.mjs and by installers/doctor.
export function loadReleasePublicKeys() {
  const raw = JSON.parse(readFileSync(PUBLIC_KEYS_PATH, "utf8"));
  return {
    ed25519: createPublicKey({ key: Buffer.from(raw.ed25519.publicKey, "base64"), format: "der", type: "spki" }),
    mldsa44: new Uint8Array(Buffer.from(raw.mldsa44.publicKey, "base64")),
  };
}
