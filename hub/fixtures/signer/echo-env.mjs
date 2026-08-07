// Test fixture only. Writes the child's actual process.env to FIXTURE_OUT as
// JSON, proving what environment signer-exec.mjs actually handed the child.
import { writeFileSync } from "node:fs";

process.stdin.resume();
process.stdin.on("end", () => {
  writeFileSync(process.env.FIXTURE_OUT, JSON.stringify(process.env));
  process.stdout.write("AA==\n");
  process.exit(0);
});
