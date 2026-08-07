// Test fixture only. Exits nonzero without producing a signature, proving
// signer-exec.mjs never accepts output from a failed signer process.
process.stdin.resume();
process.stdin.on("end", () => process.exit(3));
