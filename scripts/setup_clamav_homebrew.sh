#!/bin/sh
set -eu

BREW_PREFIX="${HOMEBREW_PREFIX:-$(brew --prefix)}"
ETC_DIR="$BREW_PREFIX/etc/clamav"
VAR_DIR="$BREW_PREFIX/var/lib/clamav"
LOG_DIR="$BREW_PREFIX/var/log/clamav"
RUN_DIR="$BREW_PREFIX/var/run/clamav"
CERTS_DIR="$ETC_DIR/certs"

mkdir -p "$VAR_DIR" "$LOG_DIR" "$RUN_DIR"

copy_sample_if_missing() {
  sample_path="$1"
  target_path="$2"
  if [ ! -f "$target_path" ]; then
    cp "$sample_path" "$target_path"
  fi
}

ensure_line() {
  file_path="$1"
  key="$2"
  value="$3"

  perl -0pi -e "s|^${key}[[:space:]].*$||mg" "$file_path"
  printf '\n%s %s\n' "$key" "$value" >> "$file_path"
}

disable_example() {
  file_path="$1"
  perl -0pi -e 's/^[[:space:]]*Example[[:space:]]*$\n?//mg' "$file_path"
}

copy_sample_if_missing "$ETC_DIR/freshclam.conf.sample" "$ETC_DIR/freshclam.conf"
disable_example "$ETC_DIR/freshclam.conf"
ensure_line "$ETC_DIR/freshclam.conf" "DatabaseDirectory" "$VAR_DIR"
ensure_line "$ETC_DIR/freshclam.conf" "CVDCertsDirectory" "$CERTS_DIR"
ensure_line "$ETC_DIR/freshclam.conf" "UpdateLogFile" "$LOG_DIR/freshclam.log"
ensure_line "$ETC_DIR/freshclam.conf" "LogTime" "yes"
ensure_line "$ETC_DIR/freshclam.conf" "DatabaseMirror" "database.clamav.net"
ensure_line "$ETC_DIR/freshclam.conf" "Checks" "12"

copy_sample_if_missing "$ETC_DIR/clamd.conf.sample" "$ETC_DIR/clamd.conf"
disable_example "$ETC_DIR/clamd.conf"
ensure_line "$ETC_DIR/clamd.conf" "DatabaseDirectory" "$VAR_DIR"
ensure_line "$ETC_DIR/clamd.conf" "CVDCertsDirectory" "$CERTS_DIR"
ensure_line "$ETC_DIR/clamd.conf" "LocalSocket" "$RUN_DIR/clamd.sock"
ensure_line "$ETC_DIR/clamd.conf" "LogFile" "$LOG_DIR/clamd.log"
ensure_line "$ETC_DIR/clamd.conf" "LogTime" "yes"
ensure_line "$ETC_DIR/clamd.conf" "FixStaleSocket" "yes"

printf 'Configured ClamAV in %s\n' "$ETC_DIR"
printf 'Database directory: %s\n' "$VAR_DIR"
