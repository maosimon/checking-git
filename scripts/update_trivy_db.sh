#!/bin/sh
set -eu

TRIVY_BIN="${TRIVY_BIN:-$(command -v trivy)}"
TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db:2}"
TRIVY_JAVA_DB_REPOSITORY="${TRIVY_JAVA_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-java-db:1}"

if [ -z "${TRIVY_BIN}" ]; then
  echo "trivy not found in PATH" >&2
  exit 1
fi

"$TRIVY_BIN" image --download-db-only --no-progress --db-repository "$TRIVY_DB_REPOSITORY"
"$TRIVY_BIN" image --download-java-db-only --no-progress --java-db-repository "$TRIVY_JAVA_DB_REPOSITORY"

printf 'Trivy vulnerability databases updated.\n'
