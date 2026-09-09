#!/usr/bin/env bash
set -euo pipefail

DEPLOYMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_DIR="${DEPLOYMENT_DIR}/.secrets"

compose() {
  "$DEPLOYMENT_DIR/compose.sh" "$@"
}

cd "$DEPLOYMENT_DIR"
umask 077
mkdir -p "$SECRETS_DIR"
touch "$SECRETS_DIR/access_token" "$SECRETS_DIR/encryption_key"
chmod 700 "$SECRETS_DIR"
chmod 600 "$SECRETS_DIR/access_token" "$SECRETS_DIR/encryption_key"

compose build \
  --build-arg "SECURITY_REFRESH=$(date -u +%Y-%m-%d)" \
  scankeep
compose run --rm --no-deps \
  --user "$(id -u):$(id -g)" \
  --entrypoint python \
  --volume "${SECRETS_DIR}:/secrets" \
  scankeep -m scankeep.bootstrap init /secrets

test -s "$SECRETS_DIR/access_token"
test -s "$SECRETS_DIR/encryption_key"
compose up --detach scankeep

container_id="$(compose ps -q scankeep)"
if [[ -z "$container_id" ]]; then
  echo "Scankeep container was not created." >&2
  exit 1
fi
deadline=$((SECONDS + 120))
while true; do
  status="$(
    docker inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
      "$container_id"
  )"
  case "$status" in
    healthy)
      break
      ;;
    unhealthy | exited | dead)
      compose logs --tail 100 scankeep >&2
      echo "Scankeep failed with status: $status" >&2
      exit 1
      ;;
  esac
  if ((SECONDS >= deadline)); then
    compose logs --tail 100 scankeep >&2
    echo "Timed out waiting for the Scankeep health check." >&2
    exit 1
  fi
  sleep 2
done

published_address="$(docker port "$container_id" 5002/tcp)"
printf 'Scankeep is healthy and published at %s (path: /scankeep).\n' \
  "$published_address"
