// Proves the browser-side, Buffer-free DER reader parses a REAL RFC 3161
// TimeStampToken from the shipped Anchor Suite relay (same live-network
// precedent as hub/anchor-client.test.mjs) — not just a hand-built fixture.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { anchorRfc3161 } from "../../hub/anchor-client.mjs";
import { parseRfc3161MessageImprint } from "../vendored/der.mjs";

test("parseRfc3161MessageImprint binds a live FreeTSA token to the digest it was requested for", { timeout: 40_000 }, async () => {
  const hash = createHash("sha256").update(`helm-u3-der-fixture-${Date.now()}`).digest("hex");
  const anchor = await anchorRfc3161(hash, { ca: "freetsa" });
  const { hashedMessageHex, genTime, policyOid } = parseRfc3161MessageImprint(anchor.der);
  assert.equal(hashedMessageHex, hash);
  assert.match(genTime, /^\d{14}Z$/);
  assert.ok(policyOid.length > 0);
});

test("parseRfc3161MessageImprint throws on non-DER input rather than silently mis-parsing", () => {
  assert.throws(() => parseRfc3161MessageImprint(Buffer.from("not cms der").toString("base64")));
});
