#!/usr/bin/env bash
set -euo pipefail

DEPLOYMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${DEPLOYMENT_DIR}/.secrets"

cd "$DEPLOYMENT_DIR"
if [[ ! -s "$SECRETS_DIR/encryption_key" ]]; then
  echo "Encryption key not found. Run ./deploy.sh first." >&2
  exit 1
fi

"$DEPLOYMENT_DIR/compose.sh" run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  --entrypoint python \
  --volume "${SECRETS_DIR}:/secrets" \
  scankeep -m scankeep.bootstrap rotate-access-token /secrets

"$DEPLOYMENT_DIR/deploy.sh"
