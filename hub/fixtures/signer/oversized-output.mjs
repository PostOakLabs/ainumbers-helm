// Test fixture only. Writes far more than any reasonable signature-size cap
// to stdout, proving signer-exec.mjs's byte cap kills it rather than
// buffering an unbounded amount of child output.
process.stdin.resume();
process.stdout.write("A".repeat(200_000));
