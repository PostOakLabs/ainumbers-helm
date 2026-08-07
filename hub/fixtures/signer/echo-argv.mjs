// Test fixture only — never shipped as a real signer. Writes the argv it
// actually received (everything after this script's own path) to
// FIXTURE_OUT as JSON, so a caller can prove argv fidelity survived
// spawn(..., {shell:false}) with metacharacter-laden arguments. Drains
// stdin (the digest) without inspecting it, then emits a dummy base64 line
// on stdout — the caller is expected to treat that as an invalid signature.
import { writeFileSync } from "node:fs";

process.stdin.resume();
process.stdin.on("end", () => {
  writeFileSync(process.env.FIXTURE_OUT, JSON.stringify(process.argv.slice(2)));
  process.stdout.write("AA==\n");
  process.exit(0);
});
