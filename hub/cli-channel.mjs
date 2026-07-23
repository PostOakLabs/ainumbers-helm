// CLI channel: named pipe (Windows) / UDS (unix), newline-delimited JSON.
// Trust boundary is the OS (same-user pipe ACL / 0600 socket file), not the
// bearer token — this is the local `helm` CLI talking to `helmd`, not a browser.
import { createServer } from "node:net";
import { existsSync, unlinkSync, chmodSync } from "node:fs";
import { platform } from "node:os";
import { statePath } from "./state-dir.mjs";
import { log } from "./log.mjs";

export function cliChannelPath() {
  return platform() === "win32" ? "\\\\.\\pipe\\helmd" : statePath("helmd.sock");
}

export function createCliChannel(handlers) {
  const path = cliChannelPath();
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
