// One-shot: enable this repo's committed git hooks for the current clone.
//   node scripts/setup-hooks.mjs
// Points core.hooksPath at the version-controlled .githooks/ dir (Git 2.9+). Idempotent.
// Worktrees share the parent clone's .git/config, so running this ONCE covers every existing
// and future worktree of this clone. A fresh `git clone` needs it run once (no "prepare"
// npm lifecycle hook here — this script is the bootstrap).
import { execSync } from "node:child_process";

try {
  const current = (() => {
    try { return execSync("git config --get core.hooksPath", { encoding: "utf8" }).trim(); }
    catch { return ""; }
  })();
  if (current === ".githooks") {
    console.log("✓ core.hooksPath already = .githooks — commit-msg + pre-push gates active.");
    process.exit(0);
  }
  execSync("git config core.hooksPath .githooks", { stdio: "inherit" });
  console.log("✓ core.hooksPath set to .githooks — commit-msg + pre-push gates now active for this clone (and its worktrees).");
} catch (e) {
  console.error("✗ failed to set core.hooksPath:", e.message);
  process.exit(1);
}
