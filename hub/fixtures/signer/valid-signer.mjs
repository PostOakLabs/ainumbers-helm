// Test fixture only. Reads the digest on stdin, signs it with the test-only
// Ed25519 private key baked into signer-exec.test.mjs (passed via the
// FIXTURE_PRIVKEY_B64 env var, PKCS8 DER base64), and writes the base64
// signature to stdout — standing in for a real external signer tool (a
// PKCS#11 wrapper, a cloud-KMS CLI, a YubiKey tool) that would otherwise
// hold the key.
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

const privateKey = createPrivateKey({
  key: Buffer.from(process.env.FIXTURE_PRIVKEY_B64, "base64"),
  format: "der",
  type: "pkcs8",
});

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  const digest = Buffer.concat(chunks);
  const signature = cryptoSign(null, digest, privateKey);
  process.stdout.write(signature.toString("base64") + "\n");
  process.exit(0);
});
