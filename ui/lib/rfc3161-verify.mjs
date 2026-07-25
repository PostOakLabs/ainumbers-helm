// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Post Oak Labs, Inc.
// Full offline RFC 3161 verification (HELM-TSA-1, HELM-HA-BUILD-SPEC.md §2,
// closes THREAT-MODEL-P3-DELTA R15-F10 "overconfident TST-time badge under a
// hostile relay"). ../vendored/der.mjs already proves a token's messageImprint
// is BOUND to an anchored digest, with zero crypto library. This module adds the
// three checks der.mjs's header always said a browser couldn't do offline:
//   (1) CMS SignerInfo signature verifies against the embedded signer cert
//   (2) the signer cert chains to a PINNED root (../vendored/tsa-roots.mjs) —
//       never a root the token itself supplies
//   (3) genTime falls inside the signer cert's (and each chain cert's) validity
//       window, and inside a sane absolute bound
// FAIL CLOSED throughout: a thrown error or a `valid:false` field must never be
// read by a caller as anything but "did not verify". No network — pkijs is
// dynamic-imported from ../vendored/pkijs.bundle.mjs (a byte-identical copy of
// hub/vendored/anchor-suite/vendor/pkijs.bundle.mjs; see ../vendored/PORT.md's
// HELM-TSA-1 note for why it's copied rather than imported cross-repo-root — the
// UI ships as static files served only from ui/, hub/ is never HTTP-reachable)
// but never fetches a cert, CRL, or OCSP response; chain building uses ONLY the
// certs embedded in the token plus the pinned roots passed in.
import { unwrapContentInfoDer, parseRfc3161MessageImprint, base64ToBytes, bytesToHex } from "../vendored/der.mjs";
import { PINNED_TSA_ROOTS } from "../vendored/tsa-roots.mjs";

let pkijsModulePromise;
// Lazy: the pkijs bundle is ~800KB. Loading it only when a real rfc3161 anchor is
// verified keeps the Verify view's initial page weight unchanged (D2) — same
// pattern as ../lib/committee-pptx.mjs's lazy PptxGenJS load.
function loadPkijs() {
  if (!pkijsModulePromise) {
    pkijsModulePromise = import("../vendored/pkijs.bundle.mjs").then(({ pkijs, asn1js }) => {
      pkijs.setEngine("webcrypto", new pkijs.CryptoEngine({ name: "webcrypto", crypto: globalThis.crypto }));
      return { pkijs, asn1js };
    });
  }
  return pkijsModulePromise;
}

function toArrayBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function pemToCertificate(pkijs, asn1js, pem) {
  const b64 = pem.replace(/-----BEGIN CERTIFICATE-----/, "").replace(/-----END CERTIFICATE-----/, "").replace(/\s+/g, "");
  const der = base64ToBytes(b64);
  const asn1 = asn1js.fromBER(toArrayBuffer(der));
  if (asn1.offset === -1) throw new Error("pinned root is not valid DER");
  return new pkijs.Certificate({ schema: asn1.result });
}

// result shape: { messageImprint, signature, chain, validity, genTime, policyOid,
// serial } — each of the four is { checked, valid, reason? }, so the Verify view
// can render them as four independent badges (spec requirement: "never render a
// single green that implies more than was checked").
export async function verifyRfc3161Full(proofB64, expectedHashHex, { pinnedRoots = PINNED_TSA_ROOTS, now = new Date() } = {}) {
  // Structural check first — der.mjs's existing, already-reconciled parser. If
  // this throws, nothing downstream can be trusted either.
  let structural;
  try {
    structural = parseRfc3161MessageImprint(proofB64);
  } catch (err) {
    const failed = { checked: true, valid: false, reason: `structural parse failed: ${err.message}` };
    return {
      messageImprint: { checked: true, bound: false, reason: err.message },
      signature: failed,
      chain: failed,
      validity: failed,
      genTime: null,
      policyOid: null,
      serial: null,
    };
  }

  const messageImprint = {
    checked: true,
    bound: structural.hashedMessageHex === expectedHashHex,
    reason: structural.hashedMessageHex === expectedHashHex ? null : "messageImprint != anchored digest",
  };

  const result = {
    messageImprint,
    signature: { checked: false },
    chain: { checked: false },
    validity: { checked: false },
    genTime: structural.genTime,
    policyOid: structural.policyOid,
    serial: structural.serial,
  };

  // A token that doesn't even bind to this checkpoint's digest is worthless
  // regardless of how well-signed it is — don't spend the (lazy-loaded, ~800KB)
  // crypto pass on it. This mirrors the existing structural-only behavior: a
  // mismatched imprint is reported, never silently "upgraded" by an unrelated
  // valid signature.
  if (!messageImprint.bound) {
    const skipped = { checked: false, reason: "skipped — messageImprint did not bind" };
    result.signature = skipped;
    result.chain = skipped;
    result.validity = skipped;
    return result;
  }

  let pkijs, asn1js;
  try {
    ({ pkijs, asn1js } = await loadPkijs());
  } catch (err) {
    const failed = { checked: false, reason: `could not load offline verifier: ${err.message}` };
    result.signature = failed;
    result.chain = failed;
    result.validity = failed;
    return result;
  }

  let signedData, tstInfo, signerCert;
  try {
    const ciDer = unwrapContentInfoDer(proofB64);
    const asn1 = asn1js.fromBER(toArrayBuffer(ciDer));
    if (asn1.offset === -1) throw new Error("not valid DER");
    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    signedData = new pkijs.SignedData({ schema: contentInfo.content });
    if (!signedData.encapContentInfo?.eContent) throw new Error("no TSTInfo content (detached, unsupported here)");
    tstInfo = pkijs.TSTInfo.fromBER(signedData.encapContentInfo.eContent.valueBlock.valueHexView);

    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo) throw new Error("no SignerInfo");
    if (!signedData.certificates?.length) throw new Error("no certificates attached to SignedData");
    if (signerInfo.sid instanceof pkijs.IssuerAndSerialNumber) {
      signerCert = signedData.certificates.find(
        (c) => c instanceof pkijs.Certificate && c.issuer.isEqual(signerInfo.sid.issuer) && c.serialNumber.isEqual(signerInfo.sid.serialNumber)
      );
    } else {
      const keyId = signerInfo.sid.idBlock?.isConstructed ? signerInfo.sid.valueBlock.value[0].valueBlock.valueHex : signerInfo.sid.valueBlock.valueHex;
      const crypto2 = pkijs.getCrypto(true);
      for (const c of signedData.certificates) {
        if (!(c instanceof pkijs.Certificate)) continue;
        const digest = await crypto2.digest({ name: "sha-1" }, c.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
        if (bytesToHex(new Uint8Array(digest)) === bytesToHex(new Uint8Array(keyId))) {
          signerCert = c;
          break;
        }
      }
    }
    if (!signerCert) throw new Error("no embedded certificate matches SignerInfo's signer identifier");
  } catch (err) {
    const failed = { checked: true, valid: false, reason: `CMS parse failed: ${err.message}` };
    result.signature = failed;
    result.chain = failed;
    result.validity = failed;
    return result;
  }

  // (1) signature: signedAttrs message-digest == hash(TSTInfo eContent), then the
  // SignerInfo signature verifies over signedAttrs using the signer cert's key.
  // Deliberately re-derived here rather than calling pkijs's SignedData.verify()
  // — that generic method requires a `data` param (the ORIGINAL preimage) to also
  // re-check messageImprint, which this system never has (only the digest
  // travels — see ../vendored/PORT.md). messageImprint is already checked above,
  // against the digest we DO have; this block covers exactly the two checks that
  // don't need a preimage: signedAttrs integrity and the signature itself.
  try {
    const crypto2 = pkijs.getCrypto(true);
    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo.signedAttrs) throw new Error("no signedAttrs (required by RFC 3161)");
    const shaAlg = crypto2.getAlgorithmByOID(signerInfo.digestAlgorithm.algorithmId, true, "digestAlgorithm");
    const eContentBytes = signedData.encapContentInfo.eContent.valueBlock.valueHexView;
    const digest = new Uint8Array(await crypto2.digest(shaAlg.name, eContentBytes));

    let contentTypeOk = false;
    let messageDigestOk = false;
    for (const attr of signerInfo.signedAttrs.attributes) {
      if (attr.type === "1.2.840.113549.1.9.3") contentTypeOk = true;
      if (attr.type === "1.2.840.113549.1.9.4") {
        const val = new Uint8Array(attr.values[0].valueBlock.valueHexView);
        messageDigestOk = bytesToHex(val) === bytesToHex(digest);
      }
    }
    if (!contentTypeOk) throw new Error('signedAttrs missing "content-type"');
    if (!messageDigestOk) throw new Error("signedAttrs message-digest != hash(TSTInfo) — token content mismatch");

    const sigAlgId = signerInfo.signatureAlgorithm.algorithmId;
    const tbs = signerInfo.signedAttrs.encodedValue;
    const sigOk =
      sigAlgId === "1.2.840.113549.1.1.1"
        ? await crypto2.verifyWithPublicKey(tbs, signerInfo.signature, signerCert.subjectPublicKeyInfo, signerInfo.signatureAlgorithm, shaAlg.name)
        : await crypto2.verifyWithPublicKey(tbs, signerInfo.signature, signerCert.subjectPublicKeyInfo, signerInfo.signatureAlgorithm);
    if (!sigOk) throw new Error("CMS signature does not verify against the embedded signer certificate");
    result.signature = { checked: true, valid: true, reason: null };
  } catch (err) {
    result.signature = { checked: true, valid: false, reason: err.message };
  }

  // (2) chain-to-pinned-root. Independent of (1) — a chain check still runs (and
  // can still fail closed) even if the signature check above failed, so a caller
  // sees BOTH verdicts rather than one masking the other.
  let chainPath = null;
  try {
    const pinnedCerts = pinnedRoots.map((r) => ({ meta: r, cert: pemToCertificate(pkijs, asn1js, r.pem) }));
    const intermediates = signedData.certificates.filter((c) => c !== signerCert && c instanceof pkijs.Certificate && pkijs.checkCA(c, signerCert));
    const engine = new pkijs.CertificateChainValidationEngine({
      checkDate: tstInfo.genTime,
      certs: intermediates,
      trustedCerts: pinnedCerts.map((p) => p.cert),
    });
    engine.certs.push(signerCert);
    const chainResult = await engine.verify({}, pkijs.getCrypto(true));
    if (!chainResult.result) throw new Error(chainResult.resultMessage || "did not chain to a pinned root");
    chainPath = chainResult.certificatePath;
    const rootBytes = bytesToHex(new Uint8Array(chainPath.at(-1).toSchema().toBER(false)));
    const rootUsed = pinnedCerts.find((p) => bytesToHex(new Uint8Array(p.cert.toSchema().toBER(false))) === rootBytes);
    result.chain = { checked: true, valid: true, reason: null, rootName: rootUsed?.meta.name ?? null };
  } catch (err) {
    result.chain = { checked: true, valid: false, reason: err.message };
  }

  // (3) validity window: genTime must fall within the signer cert's own validity,
  // AND within every cert's validity along the resolved chain (when the chain
  // check above succeeded), AND inside a sane absolute bound so a token with a
  // wildly implausible genTime (e.g. year 1970 or 200 years out) fails even if
  // every certificate happens to be long-lived.
  try {
    const genTimeMs = tstInfo.genTime.getTime();
    const nowMs = now.getTime();
    if (!(genTimeMs > Date.UTC(2016, 0, 1) && genTimeMs < nowMs + 86_400_000)) {
      throw new Error("genTime is outside a sane absolute bound [2016-01-01, now+1day]");
    }
    const certsToCheck = chainPath ?? [signerCert];
    for (const cert of certsToCheck) {
      const nb = cert.notBefore.value.getTime();
      const na = cert.notAfter.value.getTime();
      if (!(genTimeMs >= nb && genTimeMs <= na)) {
        throw new Error(`genTime falls outside "${cert.subject.typesAndValues.map((tv) => tv.value.valueBlock.value).join(", ")}"'s validity window`);
      }
    }
    result.validity = { checked: true, valid: true, reason: null };
  } catch (err) {
    result.validity = { checked: true, valid: false, reason: err.message };
  }

  return result;
}
