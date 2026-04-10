#!/bin/sh
set -eu

brew install trivy

printf 'Trivy installed successfully.\n'
printf 'Run /Users/apple/checking-git/scripts/update_trivy_db.sh to download the local vulnerability database.\n'
