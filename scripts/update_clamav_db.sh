#!/bin/sh
set -eu

BREW_PREFIX="${HOMEBREW_PREFIX:-$(brew --prefix)}"
FRESHCLAM_BIN="${FRESHCLAM_BIN:-$BREW_PREFIX/bin/freshclam}"
CONF_FILE="${FRESHCLAM_CONF:-$BREW_PREFIX/etc/clamav/freshclam.conf}"

exec "$FRESHCLAM_BIN" --config-file="$CONF_FILE" --stdout
