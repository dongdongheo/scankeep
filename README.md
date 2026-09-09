# Scankeep

Scankeep is a standalone web service for operating SonarQube scans against
GitHub and GitLab repositories. It provides manual scans, reusable presets, UTC cron
schedules, server health checks, live branch selection, persisted logs and
results, and a dashboard that separates scanner execution from quality-gate
outcomes.

The service supports SAST operations and evidence collection. It does not
certify compliance or replace vulnerability triage, release approval, or
SonarQube governance.

## Architecture

The service uses:

- Flask and Gunicorn for the web application;
- SQLite for configuration, schedules, jobs, and reports;
- Fernet encryption for stored SonarQube and repository tokens;
- Git for branch discovery and a fresh single-branch, full-history clone;
- the official SonarScanner CLI runtime bundled into the application image.

The container does not use the host Docker socket and does not run a privileged
Docker-in-Docker sidecar.

Persistent state is stored under `/var/lib/scankeep`:

```text
scankeep.db
logs/<job-id>.log
cache/
work/
```

## Requirements

- Docker Engine with Compose v2 or `docker-compose` 1.29.2
- HTTPS network access from the container to SonarQube and GitHub or GitLab
- a Linux AMD64 or ARM64 Docker host

The image copies the platform-independent scanner distribution from the pinned
official SonarScanner image into a current multi-platform Python base and uses
an OpenJDK runtime package for the target architecture.

## Deploy with Docker Compose

From the repository root:

```bash
cd deployment
./deploy.sh
```

The script:

1. creates private secret files if they do not already contain values;
2. builds the pinned application image;
3. preserves existing secrets on every later deployment;
4. starts the service and waits for its health check.

`deploy.sh` and `compose.sh` automatically select Compose v2 or the legacy
`docker-compose` command available on the host.

On first deployment, the access token is printed once. Store it in an approved
password manager. To display the existing token later:

```bash
./show-access-token.sh
```

To replace a compromised or intentionally retired access token without
changing the encryption key:

```bash
./rotate-access-token.sh
```

The new token is printed once and Scankeep is rebuilt and restarted. Existing
saved credentials remain readable.

Open:

```text
http://localhost:5002/scankeep
```

For production, place the service behind an HTTPS reverse proxy. Do not expose
it over unencrypted HTTP outside a trusted local test environment.

To change non-secret settings:

```bash
cp .env.example .env
```

Edit `.env`, then run `./deploy.sh` again. Secret files under
`deployment/.secrets/` are intentionally excluded from Git and the image build.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `SCANKEEP_HOST` | `127.0.0.1` | Host address used to publish the service |
| `SCANKEEP_PORT` | `5002` | Published host port |
| `SCANKEEP_WORKERS` | `2` | Concurrent background scan threads |
| `SCANKEEP_GIT_TIMEOUT` | `600` | Git clone timeout in seconds |
| `SCANKEEP_SCAN_TIMEOUT` | `3600` | SonarScanner timeout in seconds |
| `SCANKEEP_SCHEDULER_POLL_SECONDS` | `30` | Schedule poll interval; minimum 5 |

Set `SCANKEEP_HOST=0.0.0.0` only when the host firewall and an external TLS
proxy provide the intended access boundary.

The application also accepts `SCANKEEP_ACCESS_TOKEN` and
`SCANKEEP_ENCRYPTION_KEY` for non-Compose development. Production Compose uses
`SCANKEEP_ACCESS_TOKEN_FILE` and `SCANKEEP_ENCRYPTION_KEY_FILE` with mounted
secret files. Startup fails when either required secret is absent or invalid.

`SCANKEEP_DATA_DIR` defaults to the package-local `data` directory outside the
container. Compose sets it to the persistent volume path.

## First use

1. Sign in with the generated Scankeep access token.
2. Add a **Security server** using an HTTPS SonarQube URL and user token.
3. Add a **Project target** with a GitHub or GitLab HTTPS clone URL, repository
   token, SonarQube project key, and optional path within the repository.
4. Open **Home > Manual scans**, select a live branch, and start a scan.
5. Use **Preset scans** for repeatable operator-triggered configurations.
6. Use **Schedules** for five-field cron expressions evaluated in UTC.
7. Open a history row to review execution, commit SHA, logs, quality gate,
   measures, and the SonarQube report link.

## Scheduling behavior

Every Compose deployment runs one Gunicorn process and one scheduler thread.
Due schedules are claimed atomically in SQLite. If a previous automatic run
for the same schedule is still queued or running, the occurrence is skipped
and the next cron time is calculated.

**Run now** starts a job immediately without changing the next cron time.
Schedules and displayed timestamps are evaluated in UTC and rendered in the
browser's local time.

In-flight jobs are owned by the running service process and are not resumed
after a restart. They are marked failed when the stopped worker is reconciled.
Plan upgrades around active scans.

## Operations

View status and logs:

```bash
cd deployment
./compose.sh ps
./compose.sh logs --follow scankeep
```

Stop without deleting data:

```bash
./compose.sh down
```

### Backup

Back up both:

- the `scankeep_data` Docker volume; and
- `deployment/.secrets/encryption_key`, stored separately and securely.

Stop the service before a simple filesystem-level volume backup so the SQLite
database, WAL files, and logs are captured consistently. Losing or rotating the
Fernet key makes saved credentials unreadable.

### Upgrade

1. Wait for active scans to finish.
2. Back up the volume and encryption key.
3. Update the source and pinned dependencies/image digest.
4. Run `deployment/deploy.sh`.
5. Sign in, check server health, and run a controlled scan.

Database schema migrations run automatically at startup.

### Rollback

Restore the previous code and image together with the matching pre-upgrade data
backup when a newer release changed the database schema. Reusing a database
migrated by newer code with an older image is not guaranteed.

## Development

Python 3.12 or later is required. From the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
SCANKEEP_ACCESS_TOKEN=development-token \
SCANKEEP_ENCRYPTION_KEY="$(
  .venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
)" \
.venv/bin/gunicorn --bind 127.0.0.1:5002 --workers 1 \
  --threads 4 scankeep.app:app
```

The direct development runtime also requires `git` and `sonar-scanner` on
`PATH`. Gunicorn is the supported production server.

Run tests from the repository root:

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt
python -W error::ResourceWarning -m unittest discover -s tests -p "test_*.py"
python -m compileall -q scankeep tests
ruff check scankeep tests
ruff format --check scankeep tests
```

## Security notes

- The API uses one shared bearer token; SSO, RBAC, and per-user audit identity
  are not implemented.
- Browser access tokens are held in session storage and cleared on sign-out.
- SonarQube and Git tokens are encrypted at rest and never returned by the API.
- Secrets are removed from Git and scanner subprocess environments.
- The container runs as a non-root user with all Linux capabilities dropped,
  `no-new-privileges`, and a read-only root filesystem.
- The service must be placed behind TLS for production use.
- Logs and non-credential metadata are not encrypted; protect the data volume.
- There is no built-in retention policy, external job queue, automatic retry,
  cancellation, or high-availability database.

Report security issues according to [SECURITY.md](SECURITY.md).

## License

Scankeep is licensed under the Apache License 2.0. SonarQube and
SonarScanner are trademarks of SonarSource SA. The bundled scanner runtime is
third-party software under its own license; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
