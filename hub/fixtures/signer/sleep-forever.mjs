// Test fixture only. Never exits on its own — proves signer-exec.mjs's
// timeout actually kills a hung signer rather than waiting forever.
process.stdin.resume();
setInterval(() => {}, 1 << 30);
