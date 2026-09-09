#!/usr/bin/env bash
set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.secrets"
TOKEN_FILE="${SECRETS_DIR}/access_token"

if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "Access token not found. Run ./deploy.sh first." >&2
  exit 1
fi

IFS= read -r token < "$TOKEN_FILE"
printf '%s\n' "$token"
