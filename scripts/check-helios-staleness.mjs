#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// Surfaces drift between helios-vendor.config.json's pinnedTag and the newest
// release actually published at github.com/a16z/helios. Companion to
// helios-vendor.config.json (HELIOS-VENDOR-1) — that config pins an exact
// release tag + self-computed SHA256 per platform asset because a16z/helios
// ships no upstream checksums (research/HELIOS-SCOPE-2026-08-06.md §2). A pin
// that never gets checked against upstream is a silent trust boundary; this
// makes the drift LOUD instead.
//
// ⛔ DOES NOT AUTO-UPDATE. Per the row's own instruction, surfacing drift is
// the deliverable, not resolving it — a new Helios tag can mean a hard-fork
// schedule change (kill-trigger note in the config), so bumping the pin is a
// deliberate human act, never something this script does for you.
//
// Kept OUT of any CI gate/workflow in this pass (HELIOS-VENDOR-1's fence is
// vendor config + this check + its test, not new CI wiring) — run it by hand,
// or wire it into a schedule in a later row once the sidecar itself exists.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = join(HERE, "helios-vendor.config.json");
const RELEASES_API = "https://api.github.com/repos/a16z/helios/releases/latest";

/** Parse a bare `MAJOR.MINOR.PATCH` tag into comparable numeric segments, or null. */
export function parseSemver(s) {
  if (typeof s !== "string") return null;
  const m = s.trim().match(/^(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** -1 / 0 / 1, comparing semver segment arrays left to right. */
export function compareSemver(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

/**
 * Pure decision function — every input injected so this is unit-testable with
 * no network. `latestRelease` is {tagName, publishedAt} or null on fetch error.
 */
export function evaluateStaleness({ pinnedTag, latestRelease, fetchError }) {
  if (fetchError) {
    return { status: "UPSTREAM-UNREACHABLE", detail: fetchError, failing: true };
  }
  const pinned = parseSemver(pinnedTag);
  if (!pinned) {
    return { status: "PIN-UNPARSEABLE", detail: `pinnedTag ${JSON.stringify(pinnedTag)} is not MAJOR.MINOR.PATCH`, failing: true };
  }
  if (!latestRelease || !latestRelease.tagName) {
    return { status: "UPSTREAM-NO-RELEASE", failing: true };
  }
  const latest = parseSemver(latestRelease.tagName);
  if (!latest) {
    return { status: "UPSTREAM-TAG-UNPARSEABLE", detail: `upstream tag ${JSON.stringify(latestRelease.tagName)} is not MAJOR.MINOR.PATCH`, failing: false };
  }
  const cmp = compareSemver(pinned, latest);
  if (cmp >= 0) {
    return { status: "OK", pinned: pinnedTag, latest: latestRelease.tagName, failing: false };
  }
  return {
    status: "PIN-STALE",
    pinned: pinnedTag,
    latest: latestRelease.tagName,
    latestPublishedAt: latestRelease.publishedAt,
    failing: false, // advisory, not a gate (see file header) — reported, never auto-fixed or CI-red
  };
}

async function fetchLatestRelease() {
  try {
    const res = await fetch(RELEASES_API, {
      headers: { Accept: "application/vnd.github+json" },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = await res.json();
    return { latestRelease: { tagName: stripControlChars(body.tag_name), publishedAt: stripControlChars(body.published_at) } };
  } catch (e) {
    return { fetchError: `${RELEASES_API}: ${String(e.message || e)}` };
  }
}

// GitHub's response is upstream-controlled; strip control/escape bytes before
// it ever reaches console.log so a compromised or MITM'd response body can't
// smuggle terminal escape sequences into our own output (phil review nit,
// HELIOS-VENDOR-1).
function stripControlChars(s) {
  return typeof s === "string" ? s.replace(/[\x00-\x1f\x7f]/g, "") : s;
}

async function main() {
  const config = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  const { latestRelease, fetchError } = await fetchLatestRelease();
  const result = evaluateStaleness({ pinnedTag: config.pinnedTag, latestRelease, fetchError });

  console.log(`pinned_tag\t${config.pinnedTag}`);
  console.log(`upstream_latest_tag\t${latestRelease ? latestRelease.tagName : "(unavailable)"}`);
  console.log(`status\t${result.status}`);

  if (result.status === "PIN-STALE") {
    console.log(
      `\nDRIFT: pin ${result.pinned} is behind upstream ${result.latest}` +
        (result.latestPublishedAt ? ` (published ${result.latestPublishedAt})` : "") +
        `. Not auto-fixed — bumping the pin means re-downloading the release assets, ` +
        `re-computing SHA256 for each, and re-reading the release notes for a hard-fork ` +
        `schedule change before trusting the new binary (see killTrigger in ${CONFIG_PATH}).`,
    );
    return; // advisory: exit 0, drift is reported not failed
  }
  if (result.failing) {
    console.error(`\nFAIL: ${result.status}${result.detail ? ` — ${result.detail}` : ""}`);
    process.exitCode = 1;
    return;
  }
  console.log(`\nOK: pin is current or ahead of upstream latest.`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
