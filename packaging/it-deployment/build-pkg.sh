#!/bin/sh
# HELM-P4-J5: builds an UNSIGNED component pkg for MDM (Jamf/Kandji/etc.)
# distribution — a recipe, not a CI-run build (D-SIGN-2/3, Apple Developer ID
# signing, is deferred per HELM-CODE-SIGNING-RESEARCH-2026-07-23.md §6, same
# reason the raw SEA binary is unsigned in docs/INSTALL.md). Run this by hand
# against a downloaded, hash-verified release binary — see
# docs/IT-DEPLOYMENT.md for the full walkthrough and the Jamf-bypasses-
# Gatekeeper caveat.
#
# Usage: ./build-pkg.sh /path/to/helmd-macos-arm64 1.2.3
set -e

BINARY="$1"
VERSION="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$BINARY" ] || [ -z "$VERSION" ]; then
  echo "usage: $0 <path-to-helmd-macos-binary> <version>" >&2
  exit 1
fi
if [ ! -f "$BINARY" ]; then
  echo "build-pkg: $BINARY not found — download + verify a release binary first (docs/INSTALL.md)" >&2
  exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PAYLOAD="$WORK/payload/usr/local/bin"
mkdir -p "$PAYLOAD"
cp "$BINARY" "$PAYLOAD/helmd"
chmod 755 "$PAYLOAD/helmd"

SCRIPTS="$WORK/scripts"
mkdir -p "$SCRIPTS"
cp "$HERE/macos-postinstall.sh" "$SCRIPTS/postinstall"
chmod 755 "$SCRIPTS/postinstall"

OUT="$HERE/AINumbersHelm-${VERSION}-unsigned.pkg"

# --sign intentionally omitted (unsigned by design, see header comment).
pkgbuild \
  --root "$WORK/payload" \
  --scripts "$SCRIPTS" \
  --identifier "co.ainumbers.helm" \
  --version "$VERSION" \
  --install-location "/" \
  "$OUT"

echo "build-pkg: wrote $OUT (UNSIGNED — Gatekeeper will block a plain double-click install; see docs/IT-DEPLOYMENT.md for the Jamf-policy exception)"
