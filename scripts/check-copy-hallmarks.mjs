#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// check-copy-hallmarks.mjs — ANTI-AI-TELL gate for helm's markdown docs
// (HELM-COPY-GATE-1). Ports the pattern set from the site repo's
// repo/scripts/check-copy-hallmarks.mjs (style rule of record:
// CONTRACT.md §1.4, doctrine memory feedback-anti-ai-tell-copy-ban, Tim
// 2026-07-11, PERMANENT). This repo is zero-dep and cannot import across
// repos, so the patterns are ported, not shared.
//
// Scope: every .md under docs/, plus README.md and SECURITY.md. Vendored
// trees (hub/vendored/, ui/vendored/) are never linted here — fixed
// upstream and re-vendored, same SKIP_DIRS shape as
// check-internal-lang-leak.mjs.
//
// Two tiers, same split as the site gate and for the same reason:
//   - Em-dash: BASELINE + RATCHET (scripts/copy-hallmarks-baseline.json,
//     --init/--update regenerates it, counts only go down, mirrors
//     check-internal-lang-leak.mjs).
//   - ANTI-AI-TELL category-3 (italics-for-emphasis, bold/italic headings,
//     "not just X but", two-tone pivots, dramatic-fragment openers,
//     validation-phrasing, filler-vocab, decorative emoji in headings):
//     ZERO TOLERANCE, NO BASELINE. Affordable only because HELM-COPY-GATE-1
//     swept and fixed every pre-existing hit before shipping this gate —
//     do not baseline this tier to turn the gate green; that ships a rule
//     that enforces nothing while advertising that it does.
//
// Markdown extraction (the real work — a literal HTML port is wrong here):
//   - Fenced code blocks (``` / ~~~) and inline `backtick spans` are
//     stripped BEFORE matching, same reason the site gate excludes
//     script/style/pre/code: an identifier or sample containing a
//     denylisted substring must not fail the gate on non-prose.
//   - Emphasis is *x* / _x_, not <em>. **bold** is legitimate markdown
//     structure (used constantly for labels like "**Repo:**"), so the
//     bold-in-headings check only fires on **/__ wrapping the ENTIRE
//     heading text (the site gate's italic/bold-heading tell is "the whole
//     heading is styled for dramatic emphasis", not "a heading contains any
//     bold span" — the latter would fire on nearly every doc here).
//   - Headings are `#`..`######` lines, not <h1>-<h6>.
//   - Link text `[text](url)` is matched; the URL is not.
//   - Frontmatter (--- delimited), HTML comments, and reference-link
//     definitions ([id]: url) are stripped before matching — not prose.
//
// Usage:
//   node scripts/check-copy-hallmarks.mjs            # gate (CI + pre-push)
//   node scripts/check-copy-hallmarks.mjs --update    # regenerate the em-dash baseline
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { resolve, dirname, relative, join, extname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const BASELINE_PATH = resolve(ROOT, "scripts", "copy-hallmarks-baseline.json");

const SKIP_DIRS = new Set(["node_modules", ".git", "vendored"]);

// Only docs/*.md + the two root docs are gated (§2 scope) — not every .md
// in the repo (e.g. not scripts/*.md if any existed, not board-style files).
function targetFiles() {
  const out = [];
  const docsDir = resolve(ROOT, "docs");
  if (existsSync(docsDir)) {
    for (const name of readdirSync(docsDir)) {
      const p = join(docsDir, name);
      if (statSync(p).isDirectory()) continue; // docs/ has no subdirs today; vendored trees live elsewhere
      if (extname(name) === ".md") out.push(p);
    }
  }
  for (const name of ["README.md", "SECURITY.md"]) {
    const p = resolve(ROOT, name);
    if (existsSync(p)) out.push(p);
  }
  return out;
}

const EMDASH = /—/g;

// --- Markdown prose extraction ---
// Order matters: strip frontmatter, then HTML comments, then fenced code
// blocks (must happen before inline-code stripping, since a fence can
// contain a lone backtick), then inline code spans, then reference-link
// definitions.
function stripFrontmatter(md) {
  if (md.startsWith("---\n") || md.startsWith("---\r\n")) {
    const end = md.indexOf("\n---", 4);
    if (end !== -1) {
      const afterNl = md.indexOf("\n", end + 1);
      return afterNl === -1 ? "" : md.slice(afterNl + 1);
    }
  }
  return md;
}

function stripFencedCode(md) {
  // ``` or ~~~ fences, any length >= 3, optional info string, to matching close.
  return md.replace(/^([ \t]*)(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1\2[ \t]*$/gm, " ");
}

function stripInlineCode(md) {
  // `code` spans, including ``code with ` backtick`` double-backtick form.
  return md.replace(/``([^`]|`(?!`))*``/g, " ").replace(/`[^`\n]*`/g, " ");
}

function stripHtmlComments(md) {
  return md.replace(/<!--[\s\S]*?-->/g, " ");
}

function stripReferenceLinkDefs(md) {
  // [id]: url "title"  -- a line-anchored reference definition, not prose.
  return md.replace(/^\s*\[[^\]]+\]:\s*\S+.*$/gm, " ");
}

// Link text only: [text](url) -> text. Applied AFTER other stripping so a
// URL containing a denylisted word is never matched, only the visible text.
function unwrapLinkText(md) {
  return md.replace(/\[([^\]]*)\]\([^)]*\)/g, "$1");
}

/** Full prose extraction for pattern-matching (everything non-prose gone). */
export function prose(mdRaw) {
  let md = stripFrontmatter(mdRaw);
  md = stripHtmlComments(md);
  md = stripFencedCode(md);
  md = stripInlineCode(md);
  md = stripReferenceLinkDefs(md);
  md = unwrapLinkText(md);
  return md;
}

/** Heading lines (# .. ######), text only, in extraction order (comments/code/frontmatter already gone by caller). */
function headings(proseText) {
  const out = [];
  for (const line of proseText.split(/\r?\n/)) {
    const m = line.match(/^#{1,6}\s+(.*)$/);
    if (m) out.push(m[1]);
  }
  return out;
}

// A heading is "styled for dramatic emphasis" when bold/italic wraps the
// WHOLE heading text, not when it merely contains a bold span (markdown
// headings routinely contain inline **bold** for a labeled term, which is
// structural, not the AI-hallmark tell the site gate targets on HTML
// h1-h6). Mirrors the site gate's intent (heading-level styling) adapted to
// markdown's much heavier legitimate use of ** for label emphasis.
const HEADING_FULLY_STYLED = /^\s*(\*\*\*|___|\*\*|__|\*|_)(?!\s).+?(?<!\s)\1\s*$/;

// --- ANTI-AI-TELL BAN (ported verbatim from repo/scripts/check-copy-hallmarks.mjs;
// site gate is the source of truth for wording/reasoning). Zero-tolerance, no baseline. ---
const NOTJUSTBUT = [
  [/\bnot\s+just\b(?:(?!\bbut\b)[^.?!]){0,80}\bbut\b/gi, '"not just X but" construction'],
  [/\bisn['’]?t\s+just\b/gi, '"isn\'t just"'],
  [/\bmore\s+than\s+just\b/gi, '"more than just"'],
];
const DRAMATIC_FRAGMENT = /\bThe (?:result|catch|takeaway|verdict|kicker|bottom line)\?/gi;
const VALIDATION_PHRASING = /\byou['’]?re\s+not\s+(?:alone|imagining\s+(?:it|things))\b/gi;
const TWOTONE_COMMA = /\b(?:it['’]?s|it is|this is|that['’]?s|there['’]?s)\s+not\s+[^,.!?]{1,70},\s+(?:it['’]?s\s+about|it['’]?s|it is|they['’]?re)\b/gi;
const TWOTONE_HIGHPRECISION = /\b(?:is|are|was|were) not (?:a|an|the )?[\w-]+\.\s+(?:It|They|This|That) (?:is|are)\b/g;
const FILLER_VOCAB = [
  [/\bdelv(?:e|es|ed|ing)\b/gi, "delve"],
  [/\btapestr(?:y|ies)\b/gi, "tapestry"],
  [/\btestament\s+to\b/gi, "testament to"],
  [/\bquiet(?:ly)?\s+(?:revolution|shift|force|power|evolution)\b/gi, "quiet(ly) X"],
  [/\bseamless(?:ly)?\b/gi, "seamless"],
  [/\bgame[\s-]?chang(?:er|ing)\b/gi, "game-changer"],
  // Narrowed to the marketing-verb collocation, same reasoning as the site gate
  // (§3): "elevated risk/scrutiny" is load-bearing domain language in this
  // repo's threat-model/security docs, not filler.
  [/\belevat(?:e|es|ed|ing)\s+(?:your|our|its|their)\s+\w+/gi, "elevate your/our/its X"],
  // Narrowed to the marketing-metaphor sense, not helm's literal UI-mechanic
  // sense ("unlock the vault", stage-unlock language) — same reasoning as §3.
  [/\bunlock(?:s|ed|ing)?\s+(?:your\s+|the\s+full\s+|new\s+|greater\s+)?(?:potential|value|growth|opportunit(?:y|ies)|insight(?:s)?|power|possibilit(?:y|ies))\b/gi, "unlock potential/value/growth (marketing sense)"],
  [/\bit['’]?s\s+worth\s+noting\b/gi, "it's worth noting"],
  [/\bin\s+today['’]?s\s+fast-paced\b/gi, "in today's fast-paced"],
];
const OVERUSE_CAP = 1;
const OVERUSE_VOCAB = [
  [/\bhonest(?:ly|y)?\b/gi, "honest"],
];
const EMOJI = /[\u{2600}-\u{27BF}\u{1F300}-\u{1FAFF}]/gu;
const EMOJI_UI_EXEMPT = new Set(["✓", "✗", "✔", "✔️", "❌", "✅", "⚠", "⚠️", "🔒", "🔏", "🚫", "☑", "☑️", "➡", "➡️", "→", "⭐", "★", "☆", "❓", "❗", "‼", "⏳", "⏱", "⏱️"]);
function nonExemptEmoji(text) {
  return (text.match(EMOJI) || []).filter((ch) => !EMOJI_UI_EXEMPT.has(ch));
}

/** Analyze one file's raw markdown text; returns null if clean. */
export function analyzeFile(raw) {
  const text = prose(raw);
  const emdash = (text.match(EMDASH) || []).length;

  const hallmarks = [];
  const heads = headings(text);
  for (const h of heads) {
    if (HEADING_FULLY_STYLED.test(h)) hallmarks.push(`bold/italic-styled heading ×1 ("${h.trim().slice(0, 60)}")`);
    const hEmoji = nonExemptEmoji(h).length;
    if (hEmoji) hallmarks.push(`emoji-in-heading ×${hEmoji}`);
  }
  for (const [re, label] of NOTJUSTBUT) {
    const m = text.match(re) || [];
    if (m.length) hallmarks.push(`${label} ×${m.length}`);
  }
  const dramatic = (text.match(DRAMATIC_FRAGMENT) || []).length;
  if (dramatic) hallmarks.push(`dramatic-fragment ×${dramatic}`);
  const twotoneComma = (text.match(TWOTONE_COMMA) || []).length;
  if (twotoneComma) hallmarks.push(`"it's not X, it's Y" pivot ×${twotoneComma}`);
  const twotoneHP = (text.match(TWOTONE_HIGHPRECISION) || []).length;
  if (twotoneHP) hallmarks.push(`HIGH-PRECISION twotone ("It is not X. It is Y." family) ×${twotoneHP}`);
  const validation = (text.match(VALIDATION_PHRASING) || []).length;
  if (validation) hallmarks.push(`validation-phrasing ×${validation}`);
  for (const [re, label] of FILLER_VOCAB) {
    const m = text.match(re) || [];
    if (m.length) hallmarks.push(`filler-vocab "${label}" ×${m.length}`);
  }
  // Body (non-heading) decorative emoji is advisory here, same scope decision
  // as the site gate: this repo's docs use emoji as functional status/badge
  // iconography in prose (✅/⛔/⚠ status lines) that overlaps the emoji ranges.
  const bodyEmoji = nonExemptEmoji(text).length - heads.reduce((s, h) => s + nonExemptEmoji(h).length, 0);

  const overuse = {};
  for (const [re, label] of OVERUSE_VOCAB) {
    const n = (text.match(re) || []).length;
    if (n) overuse[label] = n;
  }

  if (emdash || hallmarks.length || Object.keys(overuse).length || bodyEmoji > 0) {
    return { emdash, hallmarks, overuse, bodyEmoji };
  }
  return null;
}

function collectFindings() {
  const findings = {};
  for (const file of targetFiles()) {
    const rel = relative(ROOT, file).replace(/\\/g, "/");
    const f = analyzeFile(readFileSync(file, "utf8"));
    if (f) findings[rel] = f;
  }
  return findings;
}

function main() {
  const UPDATE = process.argv.includes("--init") || process.argv.includes("--update");
  const findings = collectFindings();

  if (UPDATE) {
    const baseline = {};
    for (const [rel, f] of Object.entries(findings)) {
      const overDebt = {};
      for (const [k, v] of Object.entries(f.overuse || {})) if (v > OVERUSE_CAP) overDebt[k] = v;
      const debt = f.emdash + Object.keys(overDebt).length;
      if (debt) {
        baseline[rel] = { emdash: f.emdash };
        if (Object.keys(overDebt).length) baseline[rel].overuse = overDebt;
      }
    }
    writeFileSync(BASELINE_PATH, JSON.stringify({ generated: "check-copy-hallmarks.mjs --update", baseline }, null, 2) + "\n");
    console.log(`copy-hallmarks: baseline written for ${Object.keys(baseline).length} file(s).`);
    return;
  }

  const baselineFile = existsSync(BASELINE_PATH) ? JSON.parse(readFileSync(BASELINE_PATH, "utf8")) : { baseline: {} };
  const baseline = baselineFile.baseline || {};
  const failures = [];
  const improvements = [];
  const advisories = [];

  for (const [rel, f] of Object.entries(findings)) {
    const b = baseline[rel] || { emdash: 0 };
    if (f.emdash > (b.emdash || 0)) failures.push(`${rel}: ${f.emdash} em-dash(es) in prose (baseline ${b.emdash || 0})`);
    else if (f.emdash < (b.emdash || 0)) improvements.push(`${rel}: em-dash ${b.emdash} -> ${f.emdash}`);

    const bOver = b.overuse || {};
    for (const [k, v] of Object.entries(f.overuse || {})) {
      const allowed = bOver[k] != null ? bOver[k] : OVERUSE_CAP;
      if (v > allowed) failures.push(`${rel}: "${k}" ×${v} in prose — overused (max ${allowed})`);
      else if (bOver[k] != null && v < bOver[k]) improvements.push(`${rel}: "${k}" ${bOver[k]} -> ${v}`);
    }

    // ANTI-AI-TELL: zero-tolerance, no baseline, always fails if present.
    if (f.hallmarks.length) failures.push(`${rel}: ANTI-AI-TELL hit(s): ${f.hallmarks.join("; ")}`);

    if (f.bodyEmoji > 0) advisories.push(`${rel}: ${f.bodyEmoji} emoji glyph(s) in body prose (advisory)`);
  }
  for (const rel of Object.keys(baseline)) {
    if (!findings[rel]) improvements.push(`${rel}: clean (baseline entry can be dropped)`);
  }

  if (advisories.length) {
    console.log(`copy-hallmarks ADVISORY (not failing):\n  ` + advisories.join("\n  "));
  }
  if (improvements.length) {
    console.log(`copy-hallmarks: ${improvements.length} file(s) beat the baseline — tighten with --update:\n  ` + improvements.slice(0, 10).join("\n  "));
  }
  if (failures.length) {
    console.error(`\ncopy-hallmarks: ${failures.length} FAILURE(s) — AI-writing hallmarks in reader-facing markdown:\n  ` + failures.join("\n  "));
    console.error(`\nFix the copy. Em-dashes: baseline burns down with --update. ANTI-AI-TELL hits (bold/italic-styled headings, "not just X but", two-tone pivots, dramatic fragments, validation-phrasing, filler-vocab, emoji-in-headings): zero-tolerance, no baseline — rewrite the copy.`);
    process.exitCode = 1;
    return;
  }
  console.log(`copy-hallmarks: OK (${Object.keys(baseline).length} baselined file(s) within budget, 0 ANTI-AI-TELL hits).`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
