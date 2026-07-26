// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Broken-journal recovery (HELM-JOURNAL-REPAIR-1). A corrupted journal.db —
// e.g. a torn write from a killed/crashed prior run — used to leave the
// daemon with `process.exit(1)` and zero recovery path (HELM-TECHNICAL-
// ISSUES-2026-07-24.md §1): `backup.mjs`'s restore only works against a
// journal that already booted clean once, so an install that never
// finished starting had nothing to restore from. Tim's confirmed manual
// fix was renaming `~/.helm` out of the way and letting the daemon re-init
// — "loses nothing, since nothing ever ran to completion." This module
// automates exactly that.
import { existsSync, mkdirSync, renameSync, copyFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Renames the broken state dir aside (timestamped, NEVER deleted) and
// recreates an empty dir at the original path so the caller's next
// loadOrCreate*/openJournal calls re-init cleanly against a fresh journal +
// identity keys. config.json is carried forward — it is user preference
// (port, idle timeout, version-check URL), not trust-sensitive state, and
// has nothing to do with a torn journal write, so a customized port
// shouldn't silently revert to the default on an automatic recovery.
// Writes a crash-log file into the QUARANTINED copy recording why, so the
// detail survives after the fact — stdout from a double-click launch
// vanishes with the console window the instant it exits.
export function quarantineStateDir(dir, brokenAt, now = new Date()) {
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const quarantinePath = `${dir}.broken-${stamp}`;
  renameSync(dir, quarantinePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  const configPath = join(quarantinePath, "config.json");
  if (existsSync(configPath)) copyFileSync(configPath, join(dir, "config.json"));

  const crashLogPath = join(quarantinePath, "crash-log.json");
  writeFileSync(
    crashLogPath,
    JSON.stringify(
      {
        quarantinedAt: now.toISOString(),
        originalPath: dir,
        reason: "journal replay integrity check failed",
        brokenAt,
      },
      null,
      2
    ) + "\n",
    { mode: 0o600 }
  );

  return { quarantinePath, crashLogPath };
}
