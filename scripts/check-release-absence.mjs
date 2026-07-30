#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// Makes a tag-without-a-release LOUD.
//
// The failure this exists to catch: auto-tag-release.yml pushed
// 2026.7.26/.27/.28 (GITHUB_TOKEN-authored pushes never fire a
// tag-triggered workflow — a documented GitHub behavior, not a bug in
// this repo) and release.yml never ran for any of them. Every existing
// instrument (auto-tag-release's own run, the tag's existence) reported
// green. Nothing compared "a tag exists" against "a release exists" —
// this script is that comparison, run on its OWN schedule so it does not
// depend on release.yml running at all.
//
// Definition of "a release" (deliberate, not the only possible one):
// a GitHub Release object for the tag WITH at least one published asset.
// Not "a Release object exists" — a release created with zero assets
// (e.g. release.yml's `build` job failing after `gh release create`,
// if it ever did that) is exactly as useless to a consumer as no release
// at all. Not "release.yml's last run for that tag succeeded" — that
// signal doesn't exist for these 3 tags (the run never fired), so keying
// on it would make the gate blind to precisely the failure it targets.
// Checking the Release+assets state directly needs no run-history
// archaeology and is what a consumer of the binary actually experiences.
//
// Lookback + grace (operational thresholds picked from this repo's
// observed release.yml duration — 1-3 min per completed runs — NOT a
// promise about how fast releases happen for anyone):
//   LOOKBACK_DAYS = 90 — bounds the scan to recent tags; older tags are
//     historical fact, re-litigating them every day is noise.
//   GRACE_MINUTES = 30 — a tag pushed moments ago legitimately has no
//     release yet; 30 min is >10x the longest observed release.yml run.
//
// Own silent-failure mode (a done-criterion, not a footnote): a
// scheduled GitHub Actions workflow is automatically disabled after 60
// days with NO repository activity (any push, PR, or workflow run) —
// documented at https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#schedule.
// This repo has push activity from auto-tag-release.yml roughly daily,
// so the 60-day clock is expected to keep resetting on its own — but if
// that stops, THIS gate goes silent exactly like release.yml did. There
// is no secondary watchdog; ci.yml's schedule-independent nature (push +
// PR triggers) is what would keep surfacing repo activity even if this
// gate's own schedule ever got disabled, but that is not a guarantee.
// This is stated, not solved — GHA has no supported "watch my own
// schedule" primitive.
//
// Where the signal lands: a failing scheduled run shows red on the
// Actions tab, and GitHub's own workflow-failure notifications (email /
// web, per the repo watcher's notification settings) fire on it — the
// same channel every other CI failure in this repo uses. No new
// notification dependency is added.
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const REPO = "PostOakLabs/ainumbers-helm";
const LOOKBACK_DAYS = 90;
const GRACE_MINUTES = 30;
const CALVER_TAG = /^20\d\d\.\d+\.\d+$/; // matches release.yml's own trigger glob "20[0-9][0-9].*"

function gh(args) {
  return execFileSync("gh", args, { encoding: "utf8" });
}

// Exported so the sibling version-feed staleness gate
// (check-version-feed-staleness.mjs) can reuse the exact same notion of "a GA
// CalVer tag" instead of re-implementing it. Two gates disagreeing about what
// counts as a tag is its own silent-failure mode.
export { CALVER_TAG, gh };

export function listTags() {
  // name + target commit sha
  const out = gh(["api", `repos/${REPO}/tags`, "--paginate", "--jq", ".[] | .name + \" \" + .commit.sha"]);
  return out
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [name, sha] = line.split(" ");
      return { name, sha };
    })
    .filter((t) => CALVER_TAG.test(t.name));
}

function commitDate(sha) {
  const out = gh(["api", `repos/${REPO}/commits/${sha}`, "--jq", ".commit.committer.date"]);
  return new Date(out.trim());
}

function releaseAssetCount(tag) {
  try {
    const out = gh(["api", `repos/${REPO}/releases/tags/${tag}`, "--jq", ".assets | length"]);
    return Number(out.trim());
  } catch (e) {
    if (String(e.message || e).includes("404")) return -1; // no Release object at all
    throw e;
  }
}

export function evaluate({ now = new Date() } = {}) {
  const cutoff = new Date(now.getTime() - LOOKBACK_DAYS * 24 * 60 * 60 * 1000);
  const graceMs = GRACE_MINUTES * 60 * 1000;

  const tags = listTags();
  const rows = [];
  for (const tag of tags) {
    const pushedAt = commitDate(tag.sha);
    if (pushedAt < cutoff) continue; // outside lookback — historical, not scanned
    const ageMs = now.getTime() - pushedAt.getTime();
    if (ageMs < graceMs) {
      rows.push({ tag: tag.name, pushedAt, status: "SKIPPED-GRACE" });
      continue;
    }
    const assets = releaseAssetCount(tag.name);
    if (assets <= 0) {
      rows.push({ tag: tag.name, pushedAt, status: assets === -1 ? "NO-RELEASE" : "NO-ASSETS", assets });
    } else {
      rows.push({ tag: tag.name, pushedAt, status: "OK", assets });
    }
  }
  return rows;
}

function main() {
  const rows = evaluate();
  const failing = rows.filter((r) => r.status === "NO-RELEASE" || r.status === "NO-ASSETS");

  for (const r of rows) {
    console.log(`${r.tag}\tpushed=${r.pushedAt.toISOString()}\t${r.status}${"assets" in r ? `\tassets=${r.assets}` : ""}`);
  }

  if (failing.length > 0) {
    console.error(`\nFAIL: ${failing.length} tag(s) with no released assets: ${failing.map((r) => r.tag).join(", ")}`);
    process.exit(1);
  }
  console.log(`\nOK: 0 tagless tags in the last ${LOOKBACK_DAYS}d.`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
