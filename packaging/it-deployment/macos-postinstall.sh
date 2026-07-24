#!/bin/sh
# HELM-P4-J5: postinstall script for the unsigned component pkg (see
# packaging/it-deployment/build-pkg.sh for the pkgbuild recipe that embeds
# this). Runs as the payload's own scripts/postinstall after pkgbuild copies
# helmd-macos-<arch> into place. $2 is the target volume Installer passes;
# $HOME under a `sudo installer`/Jamf policy run resolves to root's home, not
# the logged-in user's, so re-derive the real console user explicitly —
# writing the LaunchAgent to the wrong home is a silent no-op autostart.
set -e

CONSOLE_USER=$(stat -f%Su /dev/console)
if [ -z "$CONSOLE_USER" ] || [ "$CONSOLE_USER" = "root" ]; then
  echo "helm-postinstall: no console user detected (headless/remote install) — skipping first-run launch. Run 'helmd start' once as the target user to complete setup." >&2
  exit 0
fi
USER_HOME=$(dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory | awk '{print $2}')

INSTALLED_EXE="/usr/local/bin/helmd"
if [ ! -x "$INSTALLED_EXE" ]; then
  echo "helm-postinstall: $INSTALLED_EXE missing or not executable after payload copy" >&2
  exit 1
fi

# Same first-run path an interactive install takes (writes the per-user
# LaunchAgent via hub/autostart.mjs, HELM-P4-J4) — run AS the console user,
# not root, or the LaunchAgent lands in /var/root and never autostarts the
# user's session.
sudo -u "$CONSOLE_USER" HOME="$USER_HOME" "$INSTALLED_EXE" start >/tmp/helm-postinstall.log 2>&1 &

exit 0
