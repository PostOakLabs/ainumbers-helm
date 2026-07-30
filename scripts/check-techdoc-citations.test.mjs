#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Tamper fixtures for check-techdoc-citations.mjs.
//
// A gate asserted to work but never observed failing is the most common
// false-green there is. These tests drive the real checker against a scratch
// tree and assert it goes RED for each drift class it claims to catch, and
// GREEN when nothing drifted.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { extractCitations, collectIssues, sha256File, ROOT, DOC_REL, MANIFEST_REL } from "./check-techdoc-citations.mjs";

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), "helm-techdoc-cite-"));
  const write = (rel, text) => {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  };
  write("hub/alpha.mjs", "one\ntwo\nthree\nfour\nfive\n");
  write("hub/beta.mjs", "only\n");
  const doc = "Alpha does a thing (`hub/alpha.mjs:4`).\n\nBeta does another (`hub/beta.mjs`).\n";
  const manifest = {
    doc: "doc.md",
    files: [
      { path: "hub/alpha.mjs", sha256: sha256File(join(dir, "hub/alpha.mjs")) },
      { path: "hub/beta.mjs", sha256: sha256File(join(dir, "hub/beta.mjs")) },
    ],
  };
  return { dir, doc, manifest, write, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("green when nothing drifted", () => {
  const s = scratch();
  try {
    assert.deepEqual(collectIssues(s.dir, s.doc, s.manifest), []);
  } finally {
    s.cleanup();
  }
});

test("RED when a cited file's contents changed without a re-stamp", () => {
  const s = scratch();
  try {
    s.write("hub/alpha.mjs", "one\ntwo\nthree\nfour\nfive EDITED\n");
    const issues = collectIssues(s.dir, s.doc, s.manifest);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /hub\/alpha\.mjs: CHANGED since the doc's claims were last verified/);
  } finally {
    s.cleanup();
  }
});

test("RED when a cited file is deleted", () => {
  const s = scratch();
  try {
    rmSync(join(s.dir, "hub/beta.mjs"));
    const issues = collectIssues(s.dir, s.doc, s.manifest);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /hub\/beta\.mjs: cited by the doc but the file no longer exists/);
  } finally {
    s.cleanup();
  }
});

test("RED when a citation points past end of file", () => {
  const s = scratch();
  try {
    const doc = "Alpha does a thing (`hub/alpha.mjs:99`).\n\nBeta does another (`hub/beta.mjs`).\n";
    // Re-stamp so the ONLY remaining failure is the past-EOF citation, not a digest change.
    const issues = collectIssues(s.dir, doc, s.manifest);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /hub\/alpha\.mjs: doc cites line 99 but the file is only 6 lines/);
  } finally {
    s.cleanup();
  }
});

test("RED when the doc adds a citation the manifest does not cover", () => {
  const s = scratch();
  try {
    s.write("hub/gamma.mjs", "new\n");
    const doc = s.doc + "\nGamma is new (`hub/gamma.mjs:1`).\n";
    const issues = collectIssues(s.dir, doc, s.manifest);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /hub\/gamma\.mjs: cited by the doc but NOT in the citation manifest/);
  } finally {
    s.cleanup();
  }
});

test("RED when the manifest keeps an entry the doc no longer cites", () => {
  const s = scratch();
  try {
    const doc = "Alpha does a thing (`hub/alpha.mjs:4`).\n";
    const issues = collectIssues(s.dir, doc, s.manifest);
    assert.equal(issues.length, 1);
    assert.match(issues[0], /hub\/beta\.mjs: in the citation manifest but the doc no longer cites it/);
  } finally {
    s.cleanup();
  }
});

test("extractor takes file:line, ranges, and same-paragraph continuations, and ignores file modes", () => {
  const cites = extractCitations("Vault tiers (`hub/vault.mjs:32`, `98`, `204-224`) use a mode-`0600` file.\n");
  assert.deepEqual([...cites.keys()], ["hub/vault.mjs"]);
  assert.equal(cites.get("hub/vault.mjs").maxLine, 224); // 0600 must not be read as line 600
});

test("extractor ignores prose that merely looks path-shaped", () => {
  const cites = extractCitations("It uses `node:sqlite` and `application/vnd.in-toto+json`, not `better-sqlite3`.\n");
  assert.deepEqual([...cites.keys()], []);
});

test("the real manifest covers exactly the real doc's citations", () => {
  const docText = readFileSync(join(ROOT, DOC_REL), "utf8");
  const manifest = JSON.parse(readFileSync(join(ROOT, MANIFEST_REL), "utf8"));
  const cited = new Set(extractCitations(docText).keys());
  const stamped = new Set(manifest.files.map((f) => f.path));
  assert.deepEqual([...cited].sort(), [...stamped].sort());
});
