// Secret vault (D9, HELM-H5). Per-platform OS-keychain tier first, falling
// back to an age-style AES-256-GCM encrypted file when no native store is
// reachable (headless CI, missing secret-service, etc.). Callers only ever
// see an opaque ref string — the ref is safe to persist in config/journal;
// the secret value never is. A non-secret index (ref -> backend used) lives
// alongside so vaultGet/vaultDelete find the right tier without re-probing.
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, unlinkSync, chmodSync, mkdirSync } from "node:fs";
import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from "node:crypto";
import { statePath } from "./state-dir.mjs";

const SERVICE = "ainumbers-helm";
const SCRYPT_KEYLEN = 32;

function indexPath() {
  return statePath("vault-index.json");
}

function loadIndex() {
  const p = indexPath();
  if (!existsSync(p)) return {};
  return JSON.parse(readFileSync(p, "utf8"));
}

function saveIndex(idx) {
  writeFileSync(indexPath(), JSON.stringify(idx, null, 2) + "\n", { mode: 0o600 });
  chmodSync(indexPath(), 0o600);
}

// --- File fallback tier: AES-256-GCM, scrypt-derived key, mode-0600 files ---

function fallbackDir() {
  const dir = statePath("vault");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function fallbackPassphrase() {
  const p = statePath("vault-fallback.key");
  if (existsSync(p)) {
    chmodSync(p, 0o600);
    return readFileSync(p);
  }
  const pass = randomBytes(32);
  writeFileSync(p, pass, { mode: 0o600 });
  chmodSync(p, 0o600);
  return pass;
}

function refFile(ref) {
  return `${fallbackDir()}/${Buffer.from(ref, "utf8").toString("base64url")}.json`;
}

function fileSet(ref, secret) {
  const pass = fallbackPassphrase();
  const salt = randomBytes(16);
  const key = scryptSync(pass, salt, SCRYPT_KEYLEN);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(secret), "utf8")), cipher.final()]);
  const blob = {
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
  writeFileSync(refFile(ref), JSON.stringify(blob), { mode: 0o600 });
  chmodSync(refFile(ref), 0o600);
}

function fileGet(ref) {
  const p = refFile(ref);
  if (!existsSync(p)) return null;
  const blob = JSON.parse(readFileSync(p, "utf8"));
  const pass = fallbackPassphrase();
  const key = scryptSync(pass, Buffer.from(blob.salt, "base64"), SCRYPT_KEYLEN);
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(blob.iv, "base64"));
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(blob.ciphertext, "base64")), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

function fileDelete(ref) {
  const p = refFile(ref);
  if (existsSync(p)) unlinkSync(p);
}

// --- macOS Keychain tier (security(1)) ---

function macosSet(ref, secret) {
  spawnSync("security", ["delete-generic-password", "-s", SERVICE, "-a", ref], { stdio: "ignore" });
  const r = spawnSync("security", ["add-generic-password", "-s", SERVICE, "-a", ref, "-w", JSON.stringify(secret)], {
    stdio: "ignore",
  });
  if (r.error || r.status !== 0) throw new Error("macos keychain set failed");
}

function macosGet(ref) {
  const r = spawnSync("security", ["find-generic-password", "-s", SERVICE, "-a", ref, "-w"], { encoding: "utf8" });
  if (r.error || r.status !== 0 || !r.stdout) return null;
  return JSON.parse(r.stdout.trim());
}

function macosDelete(ref) {
  spawnSync("security", ["delete-generic-password", "-s", SERVICE, "-a", ref], { stdio: "ignore" });
}

// --- Linux Secret Service tier (secret-tool, libsecret) ---

function linuxSet(ref, secret) {
  const r = spawnSync("secret-tool", ["store", "--label", `${SERVICE}:${ref}`, "service", SERVICE, "account", ref], {
    input: JSON.stringify(secret),
    encoding: "utf8",
  });
  if (r.error || r.status !== 0) throw new Error("secret-tool set failed");
}

function linuxGet(ref) {
  const r = spawnSync("secret-tool", ["lookup", "service", SERVICE, "account", ref], { encoding: "utf8" });
  if (r.error || r.status !== 0 || !r.stdout) return null;
  return JSON.parse(r.stdout.trim());
}

function linuxDelete(ref) {
  spawnSync("secret-tool", ["clear", "service", SERVICE, "account", ref], { stdio: "ignore" });
}

// --- Windows DPAPI tier (CurrentUser-scoped; ciphertext stored on disk) ---

function dpapiFile(ref) {
  return `${fallbackDir()}/${Buffer.from(ref, "utf8").toString("base64url")}.dpapi`;
}

function windowsSet(ref, secret) {
  const plaintextB64 = Buffer.from(JSON.stringify(secret), "utf8").toString("base64");
  const script =
    `$bytes = [Convert]::FromBase64String('${plaintextB64}'); ` +
    `$enc = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, ` +
    `[System.Security.Cryptography.DataProtectionScope]::CurrentUser); ` +
    `[Convert]::ToBase64String($enc)`;
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  if (r.error || r.status !== 0 || !r.stdout) throw new Error("dpapi encrypt failed");
  writeFileSync(dpapiFile(ref), r.stdout.trim(), { mode: 0o600 });
}

function windowsGet(ref) {
  const p = dpapiFile(ref);
  if (!existsSync(p)) return null;
  const encB64 = readFileSync(p, "utf8").trim();
  const script =
    `$bytes = [Convert]::FromBase64String('${encB64}'); ` +
    `$dec = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, ` +
    `[System.Security.Cryptography.DataProtectionScope]::CurrentUser); ` +
    `[Convert]::ToBase64String($dec)`;
  const r = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8" });
  if (r.error || r.status !== 0 || !r.stdout) return null;
  return JSON.parse(Buffer.from(r.stdout.trim(), "base64").toString("utf8"));
}

function windowsDelete(ref) {
  const p = dpapiFile(ref);
  if (existsSync(p)) unlinkSync(p);
}

const BACKENDS = {
  "macos-keychain": { available: () => process.platform === "darwin", set: macosSet, get: macosGet, delete: macosDelete },
  "windows-dpapi": { available: () => process.platform === "win32", set: windowsSet, get: windowsGet, delete: windowsDelete },
  "linux-secret-tool": { available: () => process.platform === "linux", set: linuxSet, get: linuxGet, delete: linuxDelete },
};

// Set a secret under an opaque ref. Tries the platform's native store first;
// on any failure (missing binary, no keyring daemon, DPAPI unavailable)
// falls back to the encrypted file tier silently. Returns which tier landed.
export function vaultSet(ref, secret) {
  const idx = loadIndex();
  for (const [name, backend] of Object.entries(BACKENDS)) {
    if (!backend.available()) continue;
    try {
      backend.set(ref, secret);
      idx[ref] = name;
      saveIndex(idx);
      return { ref, backend: name };
    } catch {
      break; // this platform's native tier is unusable right now — fall back
    }
  }
  fileSet(ref, secret);
  idx[ref] = "file-fallback";
  saveIndex(idx);
  return { ref, backend: "file-fallback" };
}

// Looks up which tier a ref was stored under (from the non-secret index) so
// get/delete don't have to re-probe every backend on every call.
export function vaultGet(ref) {
  const idx = loadIndex();
  const backendName = idx[ref];
  if (backendName && backendName !== "file-fallback" && BACKENDS[backendName]) {
    const v = BACKENDS[backendName].get(ref);
    if (v !== null) return v;
  }
  return fileGet(ref);
}

export function vaultDelete(ref) {
  const idx = loadIndex();
  const backendName = idx[ref];
  if (backendName && backendName !== "file-fallback" && BACKENDS[backendName]) {
    BACKENDS[backendName].delete(ref);
  }
  fileDelete(ref);
  delete idx[ref];
  saveIndex(idx);
}

export function vaultBackendFor(ref) {
  return loadIndex()[ref] ?? null;
}
