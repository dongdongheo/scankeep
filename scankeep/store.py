"""SQLite persistence and encrypted credential storage."""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .cron import next_cron_run


class ScankeepConfigError(RuntimeError):
    """Scankeep is missing required secure configuration."""


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


class ScankeepStore:
    def __init__(self, database_path: Path, encryption_key: str) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        database_path.parent.chmod(0o700)
        self.database_path = database_path
        self._cipher = self._build_cipher(encryption_key)
        self._initialize()
        self.database_path.chmod(0o600)

    @staticmethod
    def _build_cipher(encryption_key: str) -> Fernet | None:
        if not encryption_key:
            return None
        try:
            return Fernet(encryption_key.encode())
        except (TypeError, ValueError) as exc:
            raise ScankeepConfigError(
                "SCANKEEP_ENCRYPTION_KEY is not a valid Fernet key"
            ) from exc

    @property
    def encryption_ready(self) -> bool:
        return self._cipher is not None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            try:
                connection.execute("PRAGMA journal_mode = WAL")
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
        except Exception:
            connection.close()
            raise
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            self._migrate_legacy_schema(connection)
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_servers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    url TEXT NOT NULL,
                    token TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS project_targets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    provider TEXT NOT NULL CHECK(provider IN ('github', 'gitlab')),
                    url TEXT NOT NULL,
                    token TEXT NOT NULL,
                    security_server_id TEXT NOT NULL REFERENCES security_servers(id),
                    project_key TEXT NOT NULL,
                    scan_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id TEXT PRIMARY KEY,
                    project_target_id TEXT NOT NULL REFERENCES project_targets(id),
                    branch TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    preset_id TEXT,
                    preset_name TEXT NOT NULL DEFAULT '',
                    schedule_id TEXT,
                    schedule_name TEXT NOT NULL DEFAULT '',
                    trigger_source TEXT NOT NULL DEFAULT 'manual',
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    worker_pid INTEGER NOT NULL DEFAULT 0,
                    commit_sha TEXT NOT NULL DEFAULT '',
                    report TEXT,
                    error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                );

                CREATE TABLE IF NOT EXISTS scan_presets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    project_target_id TEXT NOT NULL REFERENCES project_targets(id),
                    branch TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS scan_jobs_created
                    ON scan_jobs(created_at DESC);
                """
            )
            self._migrate_schedule_schema(connection)
            self._ensure_column(
                connection, "scan_jobs", "label", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(connection, "scan_jobs", "preset_id", "TEXT")
            self._ensure_column(
                connection, "scan_jobs", "preset_name", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(connection, "scan_jobs", "schedule_id", "TEXT")
            self._ensure_column(
                connection, "scan_jobs", "schedule_name", "TEXT NOT NULL DEFAULT ''"
            )
            self._ensure_column(
                connection,
                "scan_jobs",
                "trigger_source",
                "TEXT NOT NULL DEFAULT 'manual'",
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    project_target_id TEXT NOT NULL REFERENCES project_targets(id),
                    branch TEXT NOT NULL,
                    label TEXT NOT NULL DEFAULT '',
                    cron_expression TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    next_run_at TEXT NOT NULL,
                    last_run_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS scan_jobs_preset
                    ON scan_jobs(preset_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS scan_jobs_schedule
                    ON scan_jobs(schedule_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS scan_schedules_due
                    ON scan_schedules(enabled, next_run_at);
                """
            )

    @staticmethod
    def _migrate_legacy_schema(connection: sqlite3.Connection) -> None:
        ScankeepStore._rename_table(connection, "sonar_servers", "security_servers")
        ScankeepStore._rename_table(connection, "repositories", "project_targets")
        ScankeepStore._rename_column(
            connection,
            "project_targets",
            "sonar_server_id",
            "security_server_id",
        )
        for table in ("scan_jobs", "scan_presets", "scan_schedules"):
            ScankeepStore._rename_column(
                connection,
                table,
                "repository_id",
                "project_target_id",
            )

    @staticmethod
    def _rename_table(connection: sqlite3.Connection, old: str, new: str) -> None:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if old not in tables or new in tables:
            return
        try:
            connection.execute(f"ALTER TABLE {old} RENAME TO {new}")
        except sqlite3.OperationalError:
            current = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if new not in current:
                raise

    @staticmethod
    def _rename_column(
        connection: sqlite3.Connection,
        table: str,
        old: str,
        new: str,
    ) -> None:
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if old not in columns or new in columns:
            return
        try:
            connection.execute(f"ALTER TABLE {table} RENAME COLUMN {old} TO {new}")
        except sqlite3.OperationalError:
            current = {
                row["name"]
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if new not in current:
                raise

    @staticmethod
    def _migrate_schedule_schema(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scan_schedules)"
            ).fetchall()
        }
        if "interval_minutes" not in columns or "cron_expression" in columns:
            return
        connection.execute(
            "ALTER TABLE scan_schedules RENAME TO scan_schedules_interval"
        )
        connection.execute(
            """
            CREATE TABLE scan_schedules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                project_target_id TEXT NOT NULL REFERENCES project_targets(id),
                branch TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                cron_expression TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                next_run_at TEXT NOT NULL,
                last_run_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        rows = connection.execute("SELECT * FROM scan_schedules_interval").fetchall()
        for row in rows:
            expression = ScankeepStore._legacy_interval_cron(row["interval_minutes"])
            connection.execute(
                """
                INSERT INTO scan_schedules(
                    id, name, project_target_id, branch, label, cron_expression,
                    enabled, next_run_at, last_run_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["id"],
                    row["name"],
                    row["project_target_id"],
                    row["branch"],
                    row["label"],
                    expression or "0 0 * * *",
                    row["enabled"] if expression else 0,
                    row["next_run_at"],
                    row["last_run_at"],
                    row["created_at"],
                    row["updated_at"],
                ),
            )
        connection.execute("DROP TABLE scan_schedules_interval")

    @staticmethod
    def _legacy_interval_cron(interval_minutes: int) -> str:
        if 0 < interval_minutes < 60 and 60 % interval_minutes == 0:
            return f"*/{interval_minutes} * * * *"
        if interval_minutes % 60 == 0:
            hours = interval_minutes // 60
            if 0 < hours < 24 and 24 % hours == 0:
                return f"0 */{hours} * * *"
        if interval_minutes == 1440:
            return "0 0 * * *"
        if interval_minutes == 10080:
            return "0 0 * * 0"
        return ""

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection,
        table: str,
        column: str,
        definition: str,
    ) -> None:
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            try:
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                )
            except sqlite3.OperationalError:
                current = {
                    row["name"]
                    for row in connection.execute(
                        f"PRAGMA table_info({table})"
                    ).fetchall()
                }
                if column not in current:
                    raise

    def _encrypt(self, value: str) -> str:
        if not self._cipher:
            raise ScankeepConfigError(
                "SCANKEEP_ENCRYPTION_KEY must be configured before saving credentials"
            )
        return self._cipher.encrypt(value.encode()).decode()

    def _decrypt(self, value: str) -> str:
        if not self._cipher:
            raise ScankeepConfigError("SCANKEEP_ENCRYPTION_KEY is not configured")
        try:
            return self._cipher.decrypt(value.encode()).decode()
        except InvalidToken as exc:
            raise ScankeepConfigError(
                "stored credentials cannot be decrypted with the configured key"
            ) from exc

    @staticmethod
    def _public_server(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "url": row["url"],
            "has_token": bool(row["token"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _public_project_target(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "provider": row["provider"],
            "url": row["url"],
            "has_token": bool(row["token"]),
            "security_server_id": row["security_server_id"],
            "security_server_name": row["security_server_name"],
            "server_url": row["server_url"],
            "project_key": row["project_key"],
            "scan_path": row["scan_path"],
            "created_at": row["created_at"],
        }

    def add_server(self, name: str, url: str, token: str) -> dict[str, Any]:
        server_id = str(uuid.uuid4())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO security_servers(id, name, url, token, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (server_id, name, url, self._encrypt(token), utc_now()),
            )
        return self.get_server(server_id)

    def list_servers(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM security_servers ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [self._public_server(row) for row in rows]

    def get_server(
        self, server_id: str, *, include_token: bool = False
    ) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM security_servers WHERE id = ?", (server_id,)
            ).fetchone()
        if not row:
            raise KeyError(server_id)
        server = self._public_server(row)
        if include_token:
            server["token"] = self._decrypt(row["token"])
        return server

    def delete_server(self, server_id: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM security_servers WHERE id = ?", (server_id,)
            )
            if not cursor.rowcount:
                raise KeyError(server_id)

    def update_server(
        self,
        server_id: str,
        *,
        name: str | None = None,
        url: str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        updates: dict[str, str] = {}
        if name is not None:
            updates["name"] = name
        if url is not None:
            updates["url"] = url
        if token is not None:
            updates["token"] = self._encrypt(token)
        if not updates:
            return self.get_server(server_id)
        assignments = ", ".join(f"{key} = ?" for key in updates)
        with self._connection() as connection:
            cursor = connection.execute(
                f"UPDATE security_servers SET {assignments} WHERE id = ?",
                (*updates.values(), server_id),
            )
            if not cursor.rowcount:
                raise KeyError(server_id)
        return self.get_server(server_id)

    def add_project_target(
        self,
        *,
        name: str,
        provider: str,
        url: str,
        token: str,
        security_server_id: str,
        project_key: str,
        scan_path: str,
    ) -> dict[str, Any]:
        project_target_id = str(uuid.uuid4())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO project_targets(
                    id, name, provider, url, token, security_server_id,
                    project_key, scan_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_target_id,
                    name,
                    provider,
                    url,
                    self._encrypt(token),
                    security_server_id,
                    project_key,
                    scan_path,
                    utc_now(),
                ),
            )
        return self.get_project_target(project_target_id)

    def _project_target_query(self) -> str:
        return """
            SELECT r.*, s.name AS security_server_name, s.url AS server_url
            FROM project_targets r
            JOIN security_servers s ON s.id = r.security_server_id
        """

    def list_project_targets(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                self._project_target_query() + " ORDER BY r.name COLLATE NOCASE"
            ).fetchall()
        return [self._public_project_target(row) for row in rows]

    def get_project_target(
        self, project_target_id: str, *, include_tokens: bool = False
    ) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                self._project_target_query() + " WHERE r.id = ?",
                (project_target_id,),
            ).fetchone()
        if not row:
            raise KeyError(project_target_id)
        project_target = self._public_project_target(row)
        if include_tokens:
            project_target["token"] = self._decrypt(row["token"])
            project_target["server_token"] = self.get_server(
                row["security_server_id"], include_token=True
            )["token"]
        return project_target

    def delete_project_target(self, project_target_id: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM project_targets WHERE id = ?", (project_target_id,)
            )
            if not cursor.rowcount:
                raise KeyError(project_target_id)

    def update_project_target(
        self,
        project_target_id: str,
        *,
        name: str | None = None,
        provider: str | None = None,
        url: str | None = None,
        token: str | None = None,
        security_server_id: str | None = None,
        project_key: str | None = None,
        scan_path: str | None = None,
    ) -> dict[str, Any]:
        updates: dict[str, str] = {}
        for key, value in {
            "name": name,
            "provider": provider,
            "url": url,
            "security_server_id": security_server_id,
            "project_key": project_key,
            "scan_path": scan_path,
        }.items():
            if value is not None:
                updates[key] = value
        if token is not None:
            updates["token"] = self._encrypt(token)
        if not updates:
            return self.get_project_target(project_target_id)
        assignments = ", ".join(f"{key} = ?" for key in updates)
        with self._connection() as connection:
            cursor = connection.execute(
                f"UPDATE project_targets SET {assignments} WHERE id = ?",
                (*updates.values(), project_target_id),
            )
            if not cursor.rowcount:
                raise KeyError(project_target_id)
        return self.get_project_target(project_target_id)

    def create_job(
        self,
        project_target_id: str,
        branch: str,
        *,
        label: str = "",
        preset_id: str | None = None,
        preset_name: str = "",
        schedule_id: str | None = None,
        schedule_name: str = "",
        trigger_source: str = "manual",
    ) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_jobs(
                    id, project_target_id, branch, label, preset_id, preset_name,
                    schedule_id, schedule_name, trigger_source,
                    status, phase, progress, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', 'Queued', 0, ?)
                """,
                (
                    job_id,
                    project_target_id,
                    branch,
                    label,
                    preset_id,
                    preset_name,
                    schedule_id,
                    schedule_name,
                    trigger_source,
                    utc_now(),
                ),
            )
        return self.get_job(job_id)

    def update_job(self, job_id: str, **updates: Any) -> None:
        allowed = {
            "status",
            "phase",
            "progress",
            "worker_pid",
            "commit_sha",
            "report",
            "error",
            "started_at",
            "finished_at",
        }
        fields = {key: value for key, value in updates.items() if key in allowed}
        if not fields:
            return
        if isinstance(fields.get("report"), dict):
            fields["report"] = json.dumps(fields["report"])
        assignments = ", ".join(f"{key} = ?" for key in fields)
        with self._connection() as connection:
            cursor = connection.execute(
                f"UPDATE scan_jobs SET {assignments} WHERE id = ?",
                (*fields.values(), job_id),
            )
            if not cursor.rowcount:
                raise KeyError(job_id)

    def fail_active_jobs(self) -> int:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_jobs
                SET status = 'failed',
                    phase = 'Interrupted',
                    progress = 100,
                    error = 'scan worker stopped before completion',
                    finished_at = ?
                WHERE status IN ('queued', 'running')
                """,
                (utc_now(),),
            )
        return cursor.rowcount

    def _job_query(self) -> str:
        return """
            SELECT j.*, r.name AS project_target_name, r.provider,
                   r.url AS repository_url, r.scan_path, r.project_key,
                   s.id AS security_server_id, s.name AS security_server_name,
                   s.url AS server_url
            FROM scan_jobs j
            JOIN project_targets r ON r.id = j.project_target_id
            JOIN security_servers s ON s.id = r.security_server_id
        """

    @staticmethod
    def _job(row: sqlite3.Row) -> dict[str, Any]:
        job = dict(row)
        job["report"] = json.loads(job["report"]) if job["report"] else None
        return job

    def get_job(self, job_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                self._job_query() + " WHERE j.id = ?", (job_id,)
            ).fetchone()
        if not row:
            raise KeyError(job_id)
        return self._job(row)

    def list_jobs(
        self,
        limit: int = 50,
        *,
        trigger_source: str | None = None,
        preset_id: str | None = None,
        schedule_id: str | None = None,
        project_key: str | None = None,
        project_target_id: str | None = None,
        label: str | None = None,
        status: str | None = None,
        result_status: str | None = None,
    ) -> list[dict[str, Any]]:
        filters = []
        values: list[Any] = []
        for column, value in (
            ("j.trigger_source", trigger_source),
            ("j.preset_id", preset_id),
            ("j.schedule_id", schedule_id),
            ("r.project_key", project_key),
            ("j.project_target_id", project_target_id),
            ("j.status", status),
        ):
            if value is not None:
                filters.append(f"{column} = ?")
                values.append(value)
        if label is not None:
            escaped = (
                label.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            filters.append("j.label LIKE ? ESCAPE '\\'")
            values.append(f"%{escaped}%")
        result_filters = {
            "passed": "json_extract(j.report, '$.quality_gate') = 'OK'",
            "failed": "json_extract(j.report, '$.quality_gate') = 'ERROR'",
            "pending": "j.report IS NULL AND j.status != 'failed'",
            "unavailable": "j.report IS NULL AND j.status = 'failed'",
            "other": (
                "j.report IS NOT NULL AND "
                "COALESCE(json_extract(j.report, '$.quality_gate'), '') "
                "NOT IN ('OK', 'ERROR')"
            ),
        }
        if result_status is not None:
            try:
                filters.append(result_filters[result_status])
            except KeyError as exc:
                raise ValueError("invalid result_status") from exc
        where = f" WHERE {' AND '.join(filters)}" if filters else ""
        with self._connection() as connection:
            rows = connection.execute(
                self._job_query() + where + " ORDER BY j.created_at DESC LIMIT ?",
                (*values, limit),
            ).fetchall()
        return [self._job(row) for row in rows]

    def dashboard_summary(self) -> dict[str, int]:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM security_servers) AS servers,
                    (SELECT COUNT(*) FROM project_targets) AS project_targets,
                    (SELECT COUNT(*) FROM scan_presets) AS presets,
                    (SELECT COUNT(*) FROM scan_schedules) AS schedules,
                    COUNT(*) AS scans,
                    COALESCE(SUM(status = 'succeeded'), 0) AS succeeded,
                    COALESCE(SUM(status = 'failed'), 0) AS failed,
                    COALESCE(SUM(status IN ('queued', 'running')), 0) AS active,
                    COALESCE(SUM(
                        json_extract(report, '$.quality_gate') = 'OK'
                    ), 0) AS quality_gate_passed,
                    COALESCE(SUM(
                        json_extract(report, '$.quality_gate') = 'ERROR'
                    ), 0) AS quality_gate_failed
                FROM scan_jobs
                """
            ).fetchone()
        return {key: int(value) for key, value in dict(row).items()}

    @staticmethod
    def _preset(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def add_preset(
        self,
        *,
        name: str,
        project_target_id: str,
        branch: str,
        label: str,
    ) -> dict[str, Any]:
        preset_id = str(uuid.uuid4())
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_presets(
                    id, name, project_target_id, branch, label, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (preset_id, name, project_target_id, branch, label, utc_now()),
            )
        return self.get_preset(preset_id)

    def _preset_query(self) -> str:
        return """
            SELECT p.*, r.name AS project_target_name, r.provider,
                   r.url AS repository_url, r.project_key, r.scan_path,
                   s.id AS security_server_id, s.name AS security_server_name,
                   s.url AS server_url
            FROM scan_presets p
            JOIN project_targets r ON r.id = p.project_target_id
            JOIN security_servers s ON s.id = r.security_server_id
        """

    def get_preset(self, preset_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                self._preset_query() + " WHERE p.id = ?", (preset_id,)
            ).fetchone()
        if not row:
            raise KeyError(preset_id)
        return self._preset(row)

    def list_presets(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                self._preset_query() + " ORDER BY p.name COLLATE NOCASE"
            ).fetchall()
        return [self._preset(row) for row in rows]

    def update_preset(
        self,
        preset_id: str,
        *,
        name: str,
        project_target_id: str,
        branch: str,
        label: str,
    ) -> dict[str, Any]:
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_presets
                SET name = ?, project_target_id = ?, branch = ?, label = ?
                WHERE id = ?
                """,
                (name, project_target_id, branch, label, preset_id),
            )
            if not cursor.rowcount:
                raise KeyError(preset_id)
        return self.get_preset(preset_id)

    def delete_preset(self, preset_id: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM scan_presets WHERE id = ?", (preset_id,)
            )
            if not cursor.rowcount:
                raise KeyError(preset_id)

    def add_schedule(
        self,
        *,
        name: str,
        project_target_id: str,
        branch: str,
        label: str,
        cron_expression: str,
        next_run_at: str,
    ) -> dict[str, Any]:
        schedule_id = str(uuid.uuid4())
        now = utc_now()
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_schedules(
                    id, name, project_target_id, branch, label, cron_expression,
                    enabled, next_run_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    schedule_id,
                    name,
                    project_target_id,
                    branch,
                    label,
                    cron_expression,
                    next_run_at,
                    now,
                    now,
                ),
            )
        return self.get_schedule(schedule_id)

    def _schedule_query(self) -> str:
        return """
            SELECT q.*, r.name AS project_target_name, r.provider,
                   r.url AS repository_url, r.project_key, r.scan_path,
                   s.id AS security_server_id, s.name AS security_server_name,
                   s.url AS server_url
            FROM scan_schedules q
            JOIN project_targets r ON r.id = q.project_target_id
            JOIN security_servers s ON s.id = r.security_server_id
        """

    @staticmethod
    def _schedule(row: sqlite3.Row) -> dict[str, Any]:
        schedule = dict(row)
        schedule["enabled"] = bool(schedule["enabled"])
        return schedule

    def get_schedule(self, schedule_id: str) -> dict[str, Any]:
        with self._connection() as connection:
            row = connection.execute(
                self._schedule_query() + " WHERE q.id = ?", (schedule_id,)
            ).fetchone()
        if not row:
            raise KeyError(schedule_id)
        return self._schedule(row)

    def list_schedules(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                self._schedule_query() + " ORDER BY q.name COLLATE NOCASE"
            ).fetchall()
        return [self._schedule(row) for row in rows]

    def update_schedule(
        self,
        schedule_id: str,
        *,
        enabled: bool | None = None,
        name: str | None = None,
        project_target_id: str | None = None,
        branch: str | None = None,
        label: str | None = None,
        cron_expression: str | None = None,
    ) -> dict[str, Any]:
        schedule = self.get_schedule(schedule_id)
        now = utc_now()
        next_enabled = schedule["enabled"] if enabled is None else enabled
        next_run = schedule["next_run_at"]
        expression = cron_expression or schedule["cron_expression"]
        if cron_expression or (next_enabled and not schedule["enabled"]):
            next_run = next_cron_run(expression, now)
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_schedules
                SET name = ?, project_target_id = ?, branch = ?, label = ?,
                    enabled = ?, cron_expression = ?, next_run_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    schedule["name"] if name is None else name,
                    (
                        schedule["project_target_id"]
                        if project_target_id is None
                        else project_target_id
                    ),
                    schedule["branch"] if branch is None else branch,
                    schedule["label"] if label is None else label,
                    int(next_enabled),
                    expression,
                    next_run,
                    now,
                    schedule_id,
                ),
            )
            if not cursor.rowcount:
                raise KeyError(schedule_id)
        return self.get_schedule(schedule_id)

    def delete_schedule(self, schedule_id: str) -> None:
        with self._connection() as connection:
            cursor = connection.execute(
                "DELETE FROM scan_schedules WHERE id = ?", (schedule_id,)
            )
            if not cursor.rowcount:
                raise KeyError(schedule_id)

    def record_schedule_run(self, schedule_id: str) -> None:
        now = utc_now()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                UPDATE scan_schedules
                SET last_run_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, schedule_id),
            )
            if not cursor.rowcount:
                raise KeyError(schedule_id)

    def claim_due_schedules(self, now: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                self._schedule_query()
                + " WHERE q.enabled = 1 AND q.next_run_at <= ?"
                + " ORDER BY q.next_run_at",
                (now,),
            ).fetchall()
            schedules = [self._schedule(row) for row in rows]
            for schedule in schedules:
                next_run = next_cron_run(schedule["cron_expression"], now)
                connection.execute(
                    """
                    UPDATE scan_schedules
                    SET last_run_at = ?, next_run_at = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, next_run, now, schedule["id"]),
                )
        return schedules
