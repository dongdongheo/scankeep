#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="scankeep"
cd "$(dirname "${BASH_SOURCE[0]}")"

if docker compose version >/dev/null 2>&1; then
  exec docker compose --project-name "$PROJECT_NAME" "$@"
fi
if docker-compose version >/dev/null 2>&1; then
  exec docker-compose --project-name "$PROJECT_NAME" "$@"
fi

echo "Docker Compose is required (docker compose or docker-compose)." >&2
exit 1
