#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
//
// Makes a STALE LIVE VERSION FEED loud.
//
// This is the second of the two conditions in
// HELM-RELEASE-TRIGGER-BUILD-SPEC.md §2.1. The first condition (a tag with no
// published release) is checked by the sibling script check-release-absence.mjs.
//
// WHY THIS IS NOT REDUNDANT WITH THE TAG/RELEASE CHECK:
// publishing the feed is a SEPARATE job in release.yml with a SEPARATE token
// (SITE_REPO_PUSH_TOKEN, which pushes into the site repo) and therefore its own
// independent failure mode. A GitHub Release can publish with all its assets
// while the feed a running helmd actually reads stays stale — a token that
// expired, a site-repo push that was rejected, a DreamHost deploy that did not
// run. In that state the tag/release check is silent and correct, and every
// installed helmd still believes the old version is current. Nothing else in
// the estate compares the feed against the tag.
//
// WHAT IT ASSERTS:
// the newest GA CalVer tag REACHABLE ON `main` is not newer than
// https://ainumbers.co/helm/version.json's `latest_version`.
//
// Reachability is checked, not assumed: a tag pushed onto a branch that never
// merged is not something the feed is expected to advertise, so flagging it
// would be a false alarm. `gh api compare/main...<tag>` reporting `identical`
// or `behind` means the tag's commit is an ancestor of main.
//
// A feed that cannot be fetched, cannot be parsed, or has no `latest_version`
// FAILS rather than passes. A dead feed is exactly as invisible to a running
// helmd as a stale one, and a checker that treats "I could not look" as "all
// clear" is the defect class this whole work unit exists to remove. Transient
// network trouble is absorbed by a small bounded retry (below) so that a blip
// does not become alarm fatigue, but exhausting the retries is a failure.
//
// THRESHOLDS (operational settings, ⛔ NOT a promise about how fast anything
// ships — nobody is on the hook for a publish deadline):
//   GRACE_MINUTES = 45 — the feed is published by a downstream job of the same
//     release run, so it necessarily lands after the release does. This is
//     longer than check-release-absence.mjs's 30-minute grace for exactly that
//     reason: the feed legitimately trails the tag by a release run plus a site
//     deploy. Below this age a newer tag is reported, not failed.
//   FETCH_ATTEMPTS = 3, FETCH_BACKOFF_MS = 2000 — bounded retry for transient
//     network failure only. Exhausting them fails loudly.
//
// WHERE THE SIGNAL LANDS (stated plainly, per §2.3 — no notification is implied
// that does not exist): a failing scheduled run shows RED ON THE ACTIONS TAB of
// PostOakLabs/ainumbers-helm, and GitHub's own workflow-failure notifications
// (email / web, per each repo watcher's notification settings) fire on it. That
// is the same channel every other CI failure in this repo already uses. No new
// notification dependency, no integration, no inbox rule, and ⛔ no recurring
// human duty to go and look — the notification is push, not pull. If nobody
// watches the repo, the honest description of the surface is "a red badge on
// the Actions tab", and that is what it is.
//
// THIS GATE'S OWN SILENT-FAILURE MODE (a done-criterion, not a footnote):
// GitHub automatically DISABLES a scheduled workflow after 60 days with no
// repository activity
// (https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#schedule).
// This gate rides in release-absence-gate.yml, so it shares that fate exactly:
// if the repo goes quiet for 60 days, the schedule stops and BOTH halves go
// silent in precisely the way release.yml did — no error, no notification, just
// absence. The repo's daily auto-tag-release.yml push is expected to keep
// resetting that 60-day clock as a side effect, but that is an observation
// about current behavior, not a guarantee, and there is deliberately NO
// secondary watchdog: a watchdog-for-the-watchdog is itself a scheduled
// workflow with the same failure mode, so it would move the problem rather than
// solve it. GitHub Actions has no supported "assert my own schedule still
// runs" primitive. This is stated, not solved.
import { pathToFileURL } from "node:url";
import { CALVER_TAG, gh, listTags } from "./check-release-absence.mjs";

const REPO = "PostOakLabs/ainumbers-helm";
const FEED_URL = "https://ainumbers.co/helm/version.json";
const DEFAULT_BRANCH = "main";
const GRACE_MINUTES = 45;
const FETCH_ATTEMPTS = 3;
const FETCH_BACKOFF_MS = 2000;

/** Parse a bare CalVer string into comparable numeric segments, or null. */
export function parseCalVer(s) {
  if (typeof s !== "string" || !CALVER_TAG.test(s.trim())) return null;
  return s.trim().split(".").map(Number);
}

/** -1 / 0 / 1, comparing CalVer segment arrays left to right. */
export function compareCalVer(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Pure decision function — every input is injected so this is unit-testable
 * with no network and no `gh`. `newestTag` is {name, pushedAt} or null.
 */
export function evaluateFeed({ newestTag, feed, feedError, now = new Date() }) {
  if (feedError) {
    return { status: "FEED-UNREACHABLE", detail: feedError, failing: true };
  }
  if (!feed || typeof feed !== "object") {
    return { status: "FEED-UNPARSEABLE", detail: "feed body is not a JSON object", failing: true };
  }
  const feedVersion = parseCalVer(feed.latest_version);
  if (!feedVersion) {
    return {
      status: "FEED-NO-VERSION",
      detail: `latest_version is ${JSON.stringify(feed.latest_version)}, not a bare CalVer`,
      failing: true,
    };
  }
  if (!newestTag) {
    // No GA CalVer tag reachable on the default branch at all. Nothing to be
    // behind; the tag/release half owns any tag-shaped problem.
    return { status: "NO-TAG-TO-COMPARE", feed: feed.latest_version, failing: false };
  }
  const tagVersion = parseCalVer(newestTag.name);
  const cmp = compareCalVer(feedVersion, tagVersion);
  if (cmp >= 0) {
    return { status: "OK", feed: feed.latest_version, tag: newestTag.name, failing: false };
  }
  const ageMs = now.getTime() - newestTag.pushedAt.getTime();
  if (ageMs < GRACE_MINUTES * 60 * 1000) {
    return {
      status: "SKIPPED-GRACE",
      feed: feed.latest_version,
      tag: newestTag.name,
      failing: false,
    };
  }
  return { status: "FEED-STALE", feed: feed.latest_version, tag: newestTag.name, failing: true };
}

function commitDate(sha) {
  return new Date(gh(["api", `repos/${REPO}/commits/${sha}`, "--jq", ".commit.committer.date"]).trim());
}

/** True when the tag's commit is an ancestor of the default branch. */
function reachableOnDefaultBranch(tagName) {
  try {
    const status = gh([
      "api",
      `repos/${REPO}/compare/${DEFAULT_BRANCH}...${tagName}`,
      "--jq",
      ".status",
    ]).trim();
    return status === "behind" || status === "identical";
  } catch {
    return false;
  }
}

/** Newest GA CalVer tag reachable on the default branch, or null. */
export function newestReachableTag() {
  const tags = listTags()
    .map((t) => ({ ...t, parsed: parseCalVer(t.name) }))
    .filter((t) => t.parsed)
    .sort((a, b) => compareCalVer(b.parsed, a.parsed));
  for (const t of tags) {
    if (reachableOnDefaultBranch(t.name)) {
      return { name: t.name, pushedAt: commitDate(t.sha) };
    }
  }
  return null;
}

async function fetchFeed() {
  let lastError;
  for (let attempt = 1; attempt <= FETCH_ATTEMPTS; attempt++) {
    try {
      const res = await fetch(FEED_URL, { headers: { "cache-control": "no-cache" } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return { feed: JSON.parse(await res.text()) };
    } catch (e) {
      lastError = String(e.message || e);
      if (attempt < FETCH_ATTEMPTS) {
        await new Promise((r) => setTimeout(r, FETCH_BACKOFF_MS * attempt));
      }
    }
  }
  return { feedError: `${FEED_URL}: ${lastError} (after ${FETCH_ATTEMPTS} attempts)` };
}

async function main() {
  const newestTag = newestReachableTag();
  const { feed, feedError } = await fetchFeed();
  const result = evaluateFeed({ newestTag, feed, feedError });

  console.log(`feed_url\t${FEED_URL}`);
  console.log(`newest_reachable_tag\t${newestTag ? newestTag.name : "(none)"}`);
  console.log(`feed_latest_version\t${feed?.latest_version ?? "(unavailable)"}`);
  console.log(`status\t${result.status}`);

  if (result.failing) {
    console.error(
      `\nFAIL: ${result.status}${result.detail ? ` — ${result.detail}` : ""}` +
        (result.status === "FEED-STALE"
          ? ` — ${FEED_URL} advertises ${result.feed} but ${result.tag} is the newest GA tag on ${DEFAULT_BRANCH}.` +
            " Every running helmd reads this feed, so it still believes the older version is current."
          : ""),
    );
    // process.exitCode, NOT process.exit(): forcing exit while undici's
    // keep-alive socket from fetchFeed() is still open trips a libuv assertion
    // on Windows (`!(handle->flags & UV_HANDLE_CLOSING)`) and the process dies
    // with 127 instead of 1. A gate whose failure exit code is unreliable is
    // not a gate. Setting exitCode lets the loop drain and exit 1 cleanly.
    process.exitCode = 1;
    return;
  }
  console.log(`\nOK: version feed is not behind the newest GA tag on ${DEFAULT_BRANCH}.`);
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
