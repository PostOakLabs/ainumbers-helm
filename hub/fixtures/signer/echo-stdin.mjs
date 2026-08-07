// Test fixture only. Writes exactly what it received on stdin (base64) to
// FIXTURE_OUT, proving signer-exec.mjs sent the digest and nothing else.
import { writeFileSync } from "node:fs";

const chunks = [];
process.stdin.on("data", (c) => chunks.push(c));
process.stdin.on("end", () => {
  writeFileSync(process.env.FIXTURE_OUT, Buffer.concat(chunks).toString("base64"));
  process.stdout.write("AA==\n");
  process.exit(0);
});
