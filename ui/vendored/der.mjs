// Structural-only RFC 3161 TimeStampToken reader, ported for the browser Verify
// view (HELM-U3) from TWO hub sources: the DER reader + OID decoder are
// hub/vendored/ocg/kernels/_anchor-testutil.mjs's derRead/derChildrenOf/
// derOidToString (originally Buffer-based, no crypto — run unchanged on
// Uint8Array here), and the CMS/TSTInfo field-walking structure below mirrors
// hub/vendored/ocg/kernels/_rfc3161.mjs's parseRfc3161Token. Buffer.from(...,
// "base64") is replaced with atob()-based decoding since ui/ has no Node
// builtins. The CMS SignedData signature/chain-of-trust verification in the hub
// copy uses node:crypto (X509Certificate, sign/verify) and does NOT travel —
// there is no WebCrypto equivalent for arbitrary TSA certificate chains, so a
// browser-offline verifier can prove the token's messageImprint is BOUND to the
// anchored digest (this module) but cannot prove the token's signature chains to
// a trusted TSA root. The Verify view's copy fence says so explicitly (§26.7:
// "what was checked / what was NOT"). DO NOT hand-edit the DER/OID primitives —
// resync from the hub copy if they change. Reconciliation gate:
// ui/lib/verify-vendored-reconcile.test.mjs proves this module's
// parseRfc3161MessageImprint agrees field-for-field with the hub's
// parseRfc3161Token on a real pinned fixture, so drift can't land silently.

export function base64ToBytes(b64) {
  const bin = atob(b64.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── DER (subset: definite lengths only — matches every RFC 3161/CMS producer) ──
function derRead(buf, off = 0) {
  const tag = buf[off];
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    hdr = 2 + n;
  }
  return { tag, start: off + hdr, end: off + hdr + len, header: hdr, content: buf.subarray(off + hdr, off + hdr + len) };
}
function derChildrenOf(buf, node) {
  const out = [];
  let off = node.start;
  while (off < node.end) {
    const c = derRead(buf, off);
    out.push(c);
    off = c.end;
  }
  return out;
}
function derOidToString(content) {
  const out = [Math.floor(content[0] / 40), content[0] % 40];
  let v = 0;
  for (let i = 1; i < content.length; i++) {
    v = v * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) {
      out.push(v);
      v = 0;
    }
  }
  return out.join(".");
}

const OID_TSTINFO = "1.2.840.113549.1.9.16.1.4";
const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

// A raw TSA response is TimeStampResp = SEQUENCE { status PKIStatusInfo,
// timeStampToken ContentInfo OPTIONAL } — the CMS SignedData ContentInfo this
// parser wants is the SECOND child, not the whole thing. anchor-client.mjs's
// anchorRfc3161() returns the response as-is (der: the full TimeStampResp);
// unwrap it here rather than assume every caller has already stripped the
// status wrapper — same "does this OID match" duck-typing, applied one level
// up, before falling back to treating the input as a bare ContentInfo.
function unwrapContentInfo(der) {
  const outer = derRead(der, 0);
  const [first, second] = derChildrenOf(der, outer);
  try {
    if (first && derOidToString(first.content) === OID_SIGNED_DATA) return der; // already a bare ContentInfo
  } catch { /* first child isn't an OID at all — fall through to TimeStampResp unwrap */ }
  if (second) return der.subarray(second.start - second.header, second.end); // tokenNode's own TLV, re-based to offset 0
  throw new Error("not CMS SignedData and no TimeStampResp timeStampToken to unwrap");
}

// proofB64: base64 RFC 3161 response — either a bare CMS SignedData
// ContentInfo, or a full TimeStampResp (status + ContentInfo) as
// hub/anchor-client.mjs's anchorRfc3161() returns (a checkpoint anchors[].proof
// for type "rfc3161" travels either shape depending on producer). Returns
// { hashedMessageHex, policyOid, serial, genTime } — the structural half of
// RFC 3161 verification, with zero network and zero signature/chain checking.
// Throws on malformed input; callers catch.
export function parseRfc3161MessageImprint(proofB64) {
  const der = unwrapContentInfo(base64ToBytes(proofB64));
  const ci = derRead(der, 0);
  const [oidNode, explicit0] = derChildrenOf(der, ci);
  if (derOidToString(oidNode.content) !== OID_SIGNED_DATA) throw new Error("not CMS SignedData");
  const signedData = derChildrenOf(der, explicit0)[0];
  const kids = derChildrenOf(der, signedData);
  const encapKids = derChildrenOf(der, kids[2]);
  if (derOidToString(encapKids[0].content) !== OID_TSTINFO) throw new Error("eContentType != id-ct-TSTInfo");
  const tstInfoDer = derRead(der, encapKids[1].start).content; // OCTET STRING in [0]

  const t = derChildrenOf(tstInfoDer, derRead(tstInfoDer, 0));
  const policyOid = derOidToString(t[1].content);
  const imprintKids = derChildrenOf(tstInfoDer, t[2]);
  const imprintAlg = derOidToString(derChildrenOf(tstInfoDer, imprintKids[0])[0].content);
  const hashedMessage = imprintKids[1].content;
  const serial = BigInt("0x" + bytesToHex(t[3].content)).toString(10);
  const genTime = new TextDecoder("ascii").decode(t[4].content);
  if (imprintAlg !== OID_SHA256) throw new Error("messageImprint alg is not SHA-256");
  return { hashedMessageHex: bytesToHex(hashedMessage), policyOid, serial, genTime };
}
