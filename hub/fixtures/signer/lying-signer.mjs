// Test fixture only. Returns a syntactically valid base64 blob that is NOT a
// real signature over the digest it was handed — proves verify-after-sign
// (phil condition #4) catches a lying or broken signer tool rather than
// trusting whatever comes back on stdout.
process.stdin.resume();
process.stdin.on("end", () => {
  process.stdout.write(Buffer.from("this is not a real ed25519 signature, just 64 bytes of junk!!").toString("base64") + "\n");
  process.exit(0);
});
