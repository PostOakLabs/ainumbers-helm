// Browser-side workflow_manifest_digest (SPEC.md §26.3): SHA-256 of the JCS
// canonical form. Mirrors the recursive-key-sort + minimal-JSON canonicalizer
// in hub/vendored/ocg/kernels/_hash.mjs (cgCanon) so the digest this view
// shows never diverges from what the daemon/kernels compute — kept as a
// separate small copy because ui/ ships static with no build step and
// hub/vendored isn't served to the browser.
export function cgCanon(v) {
  if (Array.isArray(v)) return v.map(cgCanon);
  if (v && typeof v === "object") {
    return Object.keys(v).sort().reduce((o, k) => ((o[k] = cgCanon(v[k])), o), {});
  }
  return v;
}

export async function manifestDigest(manifest) {
  const bytes = new TextEncoder().encode(JSON.stringify(cgCanon(manifest)));
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  const hex = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `sha256:${hex}`;
}
