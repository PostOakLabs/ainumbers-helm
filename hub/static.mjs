// Hand-rolled static handler for the served UI shell (HELM-U4, Syncthing
// pattern). No framework, no directory listing, no fs path built from the
// request — see ui-manifest.mjs for why traversal isn't reachable.
//
// Deliberately NOT gated by Origin or the bearer token: a top-level browser
// navigation to http://127.0.0.1:<port>/ carries neither (Origin is omitted
// on same-origin navigations, and there is no way to attach a custom header
// to a navigation at all), so gating the shell on either would make the page
// unloadable. The Host check (server.mjs, applied before this is ever
// reached) is the DNS-rebinding defense here; the shell itself is inert
// static assets with no secrets in it — the API routes behind it stay fully
// gated by Host + Origin + bearer, unchanged.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isSea, getAsset } from "node:sea";
import { UI_ASSETS, UI_DIR } from "./ui-manifest.mjs";

export const STATIC_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cache-Control": "no-cache",
};

function readAsset(asset) {
  if (isSea()) return Buffer.from(getAsset(asset.seaKey));
  return readFileSync(join(UI_DIR, asset.rel));
}

// doctor.mjs check: can the shell page actually be read right now (SEA
// asset embedded, or the dev-mode ui/ file present on disk)?
export function uiAssetsReadable() {
  try {
    readAsset(UI_ASSETS.get("/helm.html"));
    return true;
  } catch {
    return false;
  }
}

// Returns true if it handled the request (200 or its own error path), false
// if the path isn't a known static asset — caller falls through to the API
// router, which is what turns an unknown/traversal-y path into the normal
// `not_found` 404.
export function serveStatic(req, res, pathname) {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  const asset = UI_ASSETS.get(pathname);
  if (!asset) return false;

  let body;
  try {
    body = readAsset(asset);
  } catch {
    return false;
  }

  res.writeHead(200, { ...STATIC_HEADERS, "Content-Type": asset.contentType, "Content-Length": body.length });
  res.end(req.method === "HEAD" ? undefined : body);
  return true;
}
