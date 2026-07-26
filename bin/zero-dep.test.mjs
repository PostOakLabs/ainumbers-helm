// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-CLI-MIN-1 done-criterion: "dependencies still {} — asserted by a
// test, not eyeballed." Zero runtime deps is load-bearing doctrine here
// (survives-the-maintainer), not a preference — a CLI framework
// (commander/yargs/oclif/meow) must never sneak back in via this path.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = JSON.parse(readFileSync(join(HERE, "..", "package.json"), "utf8"));

test("package.json dependencies is empty — no runtime dependency was added", () => {
  assert.deepEqual(PKG.dependencies, {});
});

test("package.json declares a bin entry so `npm install -g .` installs helmd", () => {
  assert.equal(PKG.bin.helmd, "./bin/helmd.mjs");
});
