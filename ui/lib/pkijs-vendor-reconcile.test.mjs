// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// HELM-TSA-1: ../vendored/pkijs.bundle.mjs is a byte-identical COPY of
// hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs (copied, not cross-imported
// — see ../vendored/PORT.md for why: hub/ is never HTTP-reachable from the
// deployed static UI). This proves the copy hasn't drifted from its source —
// a failure here means re-copy per PORT.md's resync instructions, never means
// hand-edit the ui/ copy.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));

test("ui/vendored/pkijs.bundle.mjs matches hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs byte-for-byte", () => {
  const uiCopy = readFileSync(join(HERE, "..", "vendored", "pkijs.bundle.mjs"));
  const hubSource = readFileSync(join(HERE, "..", "..", "hub", "vendored", "anchor-suite", "vendor", "pkijs.bundle.mjs"));
  const uiHash = createHash("sha256").update(uiCopy).digest("hex");
  const hubHash = createHash("sha256").update(hubSource).digest("hex");
  assert.equal(uiHash, hubHash, "ui/vendored/pkijs.bundle.mjs has drifted from hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs — re-copy, don't hand-edit either file");
});
