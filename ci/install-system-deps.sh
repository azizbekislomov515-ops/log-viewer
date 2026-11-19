#!/usr/bin/env bash
# System libraries for the test suite (Qt offscreen + Qt Charts) on Debian/Ubuntu images.
# Used by CI containers; also handy on a fresh dev machine.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
$SUDO apt-get update -qq
glib=libglib2.0-0
apt-cache show libglib2.0-0t64 >/dev/null 2>&1 && glib=libglib2.0-0t64
$SUDO apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git xz-utils "$glib" libgl1 libegl1 libfontconfig1 libfreetype6 \
    libxkbcommon0 libxkbcommon-x11-0 libdbus-1-3 libx11-6 libx11-xcb1 libxcb1 \
    libxcb-cursor0 fonts-dejavu-core >/dev/null
