// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Local-only (no network) coverage for verify-vendored.mjs — the live upstream
// re-fetch path (collectUpstreamDriftIssues, inside runCLI) needs network and
// is exercised by the dedicated CI step instead (STANDING ORDERS: `npm test`
// must stay offline-runnable). This proves: (a) the real, shipped manifests
// pass today; (b) a manifest missing `license` or `pinnedSha` is caught, not
// silently accepted (HELM-VENDOR-LICENSE-1); (c) a tampered vendored byte is
// caught; (d) an unmanifested vendored tree is caught.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  collectConfigDrivenIssues,
  collectHeterogeneousIssues,
  collectSigstoreRegistryIssues,
  collectUncoveredTreeIssues,
} from "./verify-vendored.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

function sha256Str(s) {
  return createHash("sha256").update(s).digest("hex");
}

test("verify-vendored: real hub/vendored/ocg tree passes local checks (license + pinnedSha present, bytes match)", () => {
  const config = JSON.parse(readFileSync(join(HERE, "vendor.config.json"), "utf8"));
  const issues = collectConfigDrivenIssues(join(ROOT, config.destination), config);
  assert.deepEqual(issues, []);
});

test("verify-vendored: real hub/vendored/anchor-suite tree passes local checks", () => {
  const config = JSON.parse(readFileSync(join(HERE, "vendor-anchor.config.json"), "utf8"));
  const issues = collectConfigDrivenIssues(join(ROOT, config.destination), config);
  assert.deepEqual(issues, []);
});

test("verify-vendored: real hub/vendored/ssh-sig tree passes local checks", () => {
  const config = JSON.parse(readFileSync(join(HERE, "vendor-ssh-sig.config.json"), "utf8"));
  const issues = collectConfigDrivenIssues(join(ROOT, config.destination), config);
  assert.deepEqual(issues, []);
});

test("verify-vendored: real ui/vendored tree passes local checks (every entry licensed + pinned, bytes match)", () => {
  const issues = collectHeterogeneousIssues(join(ROOT, "ui/vendored"), join(ROOT, "ui/vendored/MANIFEST.json"), "ui/vendored");
  assert.deepEqual(issues, []);
});

test("verify-vendored: real repo tree has no vendored root outside the known/covered set", () => {
  const issues = collectUncoveredTreeIssues(ROOT);
  assert.deepEqual(issues, []);
});

function withTmpDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), "helm-verify-vendored-test-"));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Async sibling of withTmpDir: the sync version's finally-rmSync would fire
// before an async callback's awaited body finished.
async function withTmpDirAsync(fn) {
  const dir = mkdtempSync(join(tmpdir(), "helm-verify-vendored-test-"));
  try {
    return await fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("verify-vendored: config-driven manifest missing `license` is caught, not silently accepted", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "a.txt"), "hello");
    const fileHash = sha256Str("hello");
    writeFileSync(
      join(dir, "MANIFEST.json"),
      JSON.stringify({
        sourceRepo: "https://example.test/repo.git",
        pinnedSha: "deadbeef",
        vendoredPaths: ["a.txt"],
        fileCount: 1,
        files: [{ path: "a.txt", sha256: fileHash }],
      })
    );
    const config = { sourceRepo: "https://example.test/repo.git", pinnedSha: "deadbeef", paths: ["a.txt"], destination: "tmp" };
    const issues = collectConfigDrivenIssues(dir, config);
    assert.ok(issues.some((m) => /missing\/empty license/.test(m)), `expected a missing-license issue, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: config-driven manifest with a tampered byte is caught", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "a.txt"), "hello");
    const correctHash = sha256Str("hello");
    writeFileSync(
      join(dir, "MANIFEST.json"),
      JSON.stringify({
        sourceRepo: "https://example.test/repo.git",
        license: "MIT",
        pinnedSha: "deadbeef",
        vendoredPaths: ["a.txt"],
        fileCount: 1,
        files: [{ path: "a.txt", sha256: correctHash }],
      })
    );
    // Tamper the vendored byte after the manifest was written.
    writeFileSync(join(dir, "a.txt"), "tampered");
    const config = { sourceRepo: "https://example.test/repo.git", pinnedSha: "deadbeef", paths: ["a.txt"], destination: "tmp" };
    const issues = collectConfigDrivenIssues(dir, config);
    assert.ok(issues.some((m) => /hash mismatch/.test(m)), `expected a hash-mismatch issue, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: heterogeneous manifest entry missing pinnedSha/license is caught per-entry", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "b.txt"), "world");
    const fileHash = sha256Str("world");
    const manifestPath = join(dir, "MANIFEST.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        entries: [
          {
            classification: "third-party-vendor",
            sourceRepo: "https://example.test/upstream.git",
            // pinnedSha deliberately omitted
            // license deliberately omitted
            files: [{ path: "b.txt", sha256: fileHash }],
          },
        ],
      })
    );
    const issues = collectHeterogeneousIssues(dir, manifestPath, "tmp");
    assert.ok(issues.some((m) => /missing\/empty pinnedSha/.test(m)), `expected missing pinnedSha, got: ${JSON.stringify(issues)}`);
    assert.ok(issues.some((m) => /missing\/empty license/.test(m)), `expected missing license, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: heterogeneous manifest with an on-disk file not listed in any entry is caught", () => {
  withTmpDir((dir) => {
    writeFileSync(join(dir, "listed.txt"), "a");
    writeFileSync(join(dir, "orphan.txt"), "b");
    const listedHash = sha256Str("a");
    const manifestPath = join(dir, "MANIFEST.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        entries: [
          {
            classification: "first-party-own",
            sourceRepo: "https://example.test/repo.git",
            pinnedSha: "n/a",
            license: "Apache-2.0",
            files: [{ path: "listed.txt", sha256: listedHash }],
          },
        ],
      })
    );
    const issues = collectHeterogeneousIssues(dir, manifestPath, "tmp");
    assert.ok(issues.some((m) => /file on disk but not in MANIFEST: orphan\.txt/.test(m)), `expected orphan-file issue, got: ${JSON.stringify(issues)}`);
  });
});

test("verify-vendored: an unmanifested vendored tree is caught, not silently skipped", () => {
  withTmpDir((dir) => {
    // Mirror the real hub/vendored + ui/vendored layout, plus one NEW,
    // deliberately unmanifested tree.
    mkdirSync(join(dir, "hub", "vendored", "ocg"), { recursive: true });
    mkdirSync(join(dir, "hub", "vendored", "anchor-suite"), { recursive: true });
    mkdirSync(join(dir, "hub", "vendored", "surprise-new-vendor"), { recursive: true });
    mkdirSync(join(dir, "ui", "vendored"), { recursive: true });
    const issues = collectUncoveredTreeIssues(dir);
    assert.ok(
      issues.some((m) => /hub\/vendored\/surprise-new-vendor.*not covered/.test(m)),
      `expected the new unmanifested tree to be flagged, got: ${JSON.stringify(issues)}`
    );
  });
});

// ---------------------------------------------------------------------------
// hub/vendored/sigstore registry re-fetch comparison.
//
// The local manifest check cannot catch tamper+regenerate (the manifest is
// part of the PR under test), so these tests build a fake "registry" tarball
// in-process and inject it via fetchTarball — no network. The load-bearing
// scenario is the second one: a vendored byte flipped AND the manifest
// regenerated to match, which the pre-existing manifest check passes GREEN.
// ---------------------------------------------------------------------------
const PKG = "@example/verifier";

// Minimal ustar writer — just enough to exercise parseTar the way npm
// package tarballs do (gzip wrapper, "package/" root, regular files).
function makeTarball(files) {
  const blocks = [];
  for (const [name, content] of files) {
    const header = Buffer.alloc(512, 0);
    header.write(name.slice(0, 100), 0, "utf8");
    header.write("0000644\0", 100, "utf8"); // mode
    header.write("0000000\0", 108, "utf8"); // uid
    header.write("0000000\0", 116, "utf8"); // gid
    header.write(content.length.toString(8).padStart(11, "0") + "\0", 124, "utf8"); // size
    header.write("0".repeat(12), 136, "utf8"); // mtime
    header.write("        ", 148, "utf8"); // checksum placeholder (spaces)
    header.write("0", 156, "utf8"); // typeflag: regular file
    header.write("ustar\0", 257, "utf8");
    header.write("00", 263, "utf8");
    let sum = 0;
    for (const b of header) sum += b;
    header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "utf8");
    blocks.push(header);
    const data = Buffer.alloc(Math.ceil(content.length / 512) * 512, 0);
    content.copy(data);
    blocks.push(data);
  }
  blocks.push(Buffer.alloc(1024, 0)); // two zero blocks terminate the archive
  return gzipSync(Buffer.concat(blocks));
}

function registryTarball(fileContents) {
  return makeTarball([...fileContents].map(([name, content]) => [`package/${name}`, Buffer.from(content, "utf8")]));
}

const GENUINE_INDEX = "console.log('genuine vendored verifier');\n";
const GENUINE_LICENSE = "Apache-2.0\n";

function sha256Hex(s) {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function sigstoreManifest({ indexContent, shasum, tarballUrl }) {
  const indexHash = sha256Hex(indexContent);
  const licenseHash = sha256Hex(GENUINE_LICENSE);
  return {
    note: "test manifest",
    entries: [
      {
        classification: "third-party-vendor",
        packageName: PKG,
        sourceRepo: "https://github.com/example/verifier",
        npmTarball: tarballUrl ?? `https://registry.npmjs.org/${PKG}/-/verifier-1.0.0.tgz`,
        npmTarballShasum: shasum ?? createHash("sha1").update(registryTarball([["dist/index.js", GENUINE_INDEX], ["LICENSE", GENUINE_LICENSE]])).digest("hex"),
        pinnedSha: "1.0.0",
        license: "Apache-2.0",
        files: [
          { path: `node_modules/${PKG}/dist/index.js`, sha256: indexHash },
          { path: `node_modules/${PKG}/LICENSE`, sha256: licenseHash },
        ],
      },
    ],
  };
}

function writeVendoredTree(dir, indexContent, manifest) {
  // Mirror the real vendored layout: the manifest paths are relative to the
  // tree root and live under node_modules/< packageName >/.
  const pkgDir = join(dir, "node_modules", PKG);
  mkdirSync(join(pkgDir, "dist"), { recursive: true });
  writeFileSync(join(pkgDir, "dist", "index.js"), indexContent);
  writeFileSync(join(pkgDir, "LICENSE"), GENUINE_LICENSE);
  writeFileSync(join(dir, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
}

test("verify-vendored: sigstore registry comparison GREEN — manifest, on-disk bytes, and registry tarball all agree", async () => {
  return withTmpDirAsync(async (dir) => {
    const tarball = registryTarball([["dist/index.js", GENUINE_INDEX], ["LICENSE", GENUINE_LICENSE]]);
    writeVendoredTree(dir, GENUINE_INDEX, sigstoreManifest({ indexContent: GENUINE_INDEX }));
    const issues = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => tarball,
    });
    assert.deepEqual(issues, []);
  });
});

test("verify-vendored: sigstore registry comparison catches tamper+regenerate the manifest check passes", async () => {
  return withTmpDirAsync(async (dir) => {
    const tampered = GENUINE_INDEX.replace("genuine", "evil   "); // same length, one region flipped
    assert.notEqual(tampered, GENUINE_INDEX);
    // Attacker rewrites the vendored file AND regenerates MANIFEST.json to
    // match: the pre-existing manifest-vs-bytes check is now fully green.
    writeVendoredTree(dir, tampered, sigstoreManifest({ indexContent: tampered }));
    const localIssues = collectHeterogeneousIssues(dir, join(dir, "MANIFEST.json"), "hub/vendored/sigstore");
    assert.deepEqual(localIssues, [], "precondition: the regenerated manifest must pass the local check");

    // The registry still serves the genuine package — the gate must go red.
    const tarball = registryTarball([["dist/index.js", GENUINE_INDEX], ["LICENSE", GENUINE_LICENSE]]);
    const issues = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => tarball,
    });
    assert.ok(
      issues.some((m) => /vendored bytes DRIFT from registry tarball/.test(m)),
      `expected a vendored-bytes drift issue, got: ${JSON.stringify(issues)}`
    );
    assert.ok(
      issues.some((m) => /MANIFEST sha256 does not match registry tarball bytes/.test(m)),
      `expected a manifest-vs-registry mismatch, got: ${JSON.stringify(issues)}`
    );
  });
});

test("verify-vendored: sigstore registry comparison catches a manifest whose tarball shasum was rewritten", async () => {
  return withTmpDirAsync(async (dir) => {
    const tarball = registryTarball([["dist/index.js", GENUINE_INDEX], ["LICENSE", GENUINE_LICENSE]]);
    const attackerShasum = createHash("sha1").update(Buffer.from("attacker-controlled bytes")).digest("hex");
    writeVendoredTree(dir, GENUINE_INDEX, sigstoreManifest({ indexContent: GENUINE_INDEX, shasum: attackerShasum }));
    const issues = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => tarball,
    });
    assert.ok(
      issues.some((m) => /registry tarball shasum mismatch/.test(m)),
      `expected a shasum mismatch, got: ${JSON.stringify(issues)}`
    );
  });
});

test("verify-vendored: sigstore registry comparison refuses to fetch tarball URLs off the pinned registry host", async () => {
  return withTmpDirAsync(async (dir) => {
    writeVendoredTree(
      dir,
      GENUINE_INDEX,
      sigstoreManifest({ indexContent: GENUINE_INDEX, tarballUrl: "https://evil.example/npm/@example/verifier.tgz" })
    );
    let fetched = false;
    const issues = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => {
        fetched = true;
        return Buffer.alloc(0);
      },
    });
    assert.equal(fetched, false, "must never fetch from a non-registry host");
    assert.ok(
      issues.some((m) => /refusing to compare against an arbitrary host/.test(m)),
      `expected a host refusal, got: ${JSON.stringify(issues)}`
    );
  });
});

test("verify-vendored: sigstore registry comparison reports an unfetchable tarball as an issue, not a crash", async () => {
  return withTmpDirAsync(async (dir) => {
    writeVendoredTree(dir, GENUINE_INDEX, sigstoreManifest({ indexContent: GENUINE_INDEX }));
    const issues = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => {
        throw new Error("registry unreachable");
      },
    });
    assert.ok(
      issues.some((m) => /could not fetch.*registry unreachable/.test(m)),
      `expected a fetch-failure issue, got: ${JSON.stringify(issues)}`
    );
  });
});

test("verify-vendored: sigstore registry comparison hard-fails a dist/ file missing from the tarball, skips LICENSE-class omissions", async () => {
  return withTmpDirAsync(async (dir) => {
    // Real-world shape: sigstore-js tarballs carry dist/ but not LICENSE
    // (repo-root file). A LICENSE omission must be a visible skip, not a
    // false red; a dist/ omission must stay a hard issue.
    const partial = registryTarball([["dist/index.js", GENUINE_INDEX]]);
    writeVendoredTree(dir, GENUINE_INDEX, sigstoreManifest({ indexContent: GENUINE_INDEX }));
    const issues = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => partial,
    });
    assert.deepEqual(
      issues.filter((m) => /LICENSE/.test(m)),
      [],
      `LICENSE-class tarball omission must not be an issue, got: ${JSON.stringify(issues)}`
    );

    // Now list a dist/ file the tarball does not contain: hard issue.
    const manifest = sigstoreManifest({ indexContent: GENUINE_INDEX });
    manifest.entries[0].files.push({ path: `node_modules/${PKG}/dist/second.js`, sha256: sha256Hex("more code\n") });
    writeFileSync(join(dir, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
    const issues2 = await collectSigstoreRegistryIssues(dir, join(dir, "MANIFEST.json"), {
      fetchTarball: async () => partial,
    });
    assert.ok(
      issues2.some((m) => /absent from the registry tarball.*dist\/second\.js/.test(m)),
      `expected a dist tarball-absence issue, got: ${JSON.stringify(issues2)}`
    );
  });
});
