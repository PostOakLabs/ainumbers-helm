// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// CLI channel: named pipe (Windows) / UDS (unix), newline-delimited JSON.
// Trust boundary is the OS (same-user pipe ACL / 0600 socket file), not the
// bearer token — this is the local `helm` CLI talking to `helmd`, not a browser.
import { createServer } from "node:net";
import { existsSync, unlinkSync, chmodSync } from "node:fs";
import { platform } from "node:os";
import { statePath } from "./state-dir.mjs";
import { loadConfig } from "./config.mjs";
import { log } from "./log.mjs";

// The unix socket lives under HELM_HOME, so two installs (a checkout and a
// packaged binary, or a test run and a real daemon) never collide. The
// Windows pipe name had no such scoping — it was the bare `helmd`, shared
// process-wide by every helmd on the machine. That was survivable while the
// only verb was `pair`, but `stop` makes it consequential: a `helmd stop`
// run from one install would have stopped whichever daemon happened to own
// the pipe. Scope it by port, which is what actually distinguishes two
// daemons on one machine.
export function cliChannelPath(port) {
  const scope = port ?? loadConfig().port;
  return platform() === "win32" ? `\\\\.\\pipe\\helmd-${scope}` : statePath("helmd.sock");
}

export function createCliChannel(handlers, { port } = {}) {
  const path = cliChannelPath(port);
  if (platform() !== "win32" && existsSync(path)) unlinkSync(path);

  const server = createServer((socket) => {
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let idx;
      while ((idx = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        if (!line.trim()) continue;
        handleLine(line, socket, handlers);
      }
    });
  });

  server.listen(path, () => {
    if (platform() !== "win32") chmodSync(path, 0o600);
    log.info("cli channel listening", { path });
  });
  return server;
}

function handleLine(line, socket, handlers) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return socket.write(JSON.stringify({ error: "bad_json" }) + "\n");
  }
  const handler = handlers[msg.cmd];
  if (!handler) return socket.write(JSON.stringify({ error: "unknown_cmd" }) + "\n");
  Promise.resolve(handler(msg))
    .then((result) => socket.write(JSON.stringify({ ok: true, result }) + "\n"))
    .catch((err) => socket.write(JSON.stringify({ ok: false, error: String(err?.message || err) }) + "\n"));
}
