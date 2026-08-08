// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Test-only preload for HELM-VERIFY-CLI-1's §1.3 zero-network property test.
// Loaded via `node --require` before the target module — overrides fetch,
// dns lookup, and net.Socket's connect to throw, so the child process trips
// a canary the instant it attempts ANY network call. Deliberately a .cjs
// file: --require only runs CommonJS, but it runs before an ESM main module
// loads regardless of that main module's own type.
const net = require("node:net");
const dns = require("node:dns");

const blocked = (what) => () => {
  throw new Error(`NETWORK_BLOCKED: ${what}`);
};

globalThis.fetch = blocked("fetch");
net.Socket.prototype.connect = blocked("net.Socket.connect");
dns.lookup = blocked("dns.lookup");
dns.promises.lookup = blocked("dns.promises.lookup");
