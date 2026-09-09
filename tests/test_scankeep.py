import io
import os
import sqlite3
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from flask import Flask
from scankeep import bootstrap, connections, create_app, cron, routes
from scankeep.runner import ScanError, ScanRunner
from scankeep.scheduler import ScanScheduler
from scankeep.store import ScankeepConfigError, ScankeepStore


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "scankeep.db"
        self.key = Fernet.generate_key().decode()
        self.store = ScankeepStore(self.database, self.key)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_database_and_data_directory_are_private(self):
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o700)

    def test_credentials_are_encrypted_and_not_returned(self):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-secret"
        )
        project_target = self.store.add_project_target(
            name="Service",
            provider="gitlab",
            url="https://gitlab.example.com/group/service.git",
            token="git-secret",
            security_server_id=server["id"],
            project_key="service-key",
            scan_path="src",
        )

        self.assertNotIn("token", server)
        self.assertNotIn("token", project_target)
        private = self.store.get_project_target(
            project_target["id"], include_tokens=True
        )
        self.assertEqual(private["token"], "git-secret")
        self.assertEqual(private["server_token"], "sonar-secret")
        raw = self.database.read_bytes()
        self.assertNotIn(b"git-secret", raw)
        self.assertNotIn(b"sonar-secret", raw)

    def test_active_jobs_are_failed_during_startup_recovery(self):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-secret"
        )
        target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/agent.git",
            token="git-secret",
            security_server_id=server["id"],
            project_key="agent",
            scan_path="",
        )
        queued = self.store.create_job(target["id"], "main")
        running = self.store.create_job(target["id"], "develop")
        self.store.update_job(running["id"], status="running")

        self.assertEqual(self.store.fail_active_jobs(), 2)
        for job_id in (queued["id"], running["id"]):
            job = self.store.get_job(job_id)
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["phase"], "Interrupted")
            self.assertEqual(job["progress"], 100)
            self.assertIn("worker stopped", job["error"])
            self.assertTrue(job["finished_at"])

    def test_missing_key_prevents_saving_credentials(self):
        store = ScankeepStore(Path(self.temp_dir.name) / "no-key.db", "")
        with self.assertRaises(ScankeepConfigError):
            store.add_server("Production", "https://sonar.example.com", "secret")

    def test_presets_and_job_metadata_are_persisted(self):
        server = self.store.add_server("Sonar", "https://sonar.example.com", "token")
        project_target = self.store.add_project_target(
            name="Repo",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="repo-key",
            scan_path="",
        )
        preset = self.store.add_preset(
            name="Develop",
            project_target_id=project_target["id"],
            branch="develop",
            label="Nightly validation",
        )
        job = self.store.create_job(
            project_target["id"],
            "develop",
            label=preset["label"],
            preset_id=preset["id"],
            preset_name=preset["name"],
            trigger_source="preset",
        )

        self.assertEqual(self.store.list_presets()[0]["project_key"], "repo-key")
        stored = self.store.get_job(job["id"])
        self.assertEqual(stored["label"], "Nightly validation")
        self.assertEqual(stored["preset_name"], "Develop")
        self.assertEqual(stored["trigger_source"], "preset")
        self.assertEqual(stored["repository_url"], project_target["url"])

    def test_due_schedule_is_claimed_once_and_keeps_history_metadata(self):
        server = self.store.add_server("Sonar", "https://sonar.example.com", "token")
        project_target = self.store.add_project_target(
            name="Repo",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="repo-key",
            scan_path="",
        )
        schedule = self.store.add_schedule(
            name="Nightly",
            project_target_id=project_target["id"],
            branch="main",
            label="Nightly scan",
            cron_expression="0 * * * *",
            next_run_at="2026-08-31T00:00:00+00:00",
        )

        first = self.store.claim_due_schedules("2026-08-31T01:00:00+00:00")
        second = self.store.claim_due_schedules("2026-08-31T01:00:00+00:00")
        job = self.store.create_job(
            project_target["id"],
            "main",
            schedule_id=schedule["id"],
            schedule_name=schedule["name"],
            trigger_source="schedule",
        )

        self.assertEqual([item["id"] for item in first], [schedule["id"]])
        self.assertEqual(second, [])
        self.assertEqual(
            self.store.get_schedule(schedule["id"])["next_run_at"],
            "2026-08-31T02:00:00+00:00",
        )
        self.assertEqual(
            self.store.list_jobs(schedule_id=schedule["id"])[0]["id"], job["id"]
        )

    def test_dashboard_summary_counts_inventory_and_scan_outcomes(self):
        server = self.store.add_server("Sonar", "https://sonar.example.com", "token")
        project_target = self.store.add_project_target(
            name="Repo",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="repo-key",
            scan_path="",
        )
        self.store.add_preset(
            name="Main",
            project_target_id=project_target["id"],
            branch="main",
            label="",
        )
        self.store.add_schedule(
            name="Nightly",
            project_target_id=project_target["id"],
            branch="main",
            label="",
            cron_expression="0 0 * * *",
            next_run_at="2026-09-02T00:00:00+00:00",
        )
        passed = self.store.create_job(
            project_target["id"], "main", label="Release validation"
        )
        failed = self.store.create_job(
            project_target["id"],
            "main",
            label="Nightly scan",
            trigger_source="schedule",
        )
        active = self.store.create_job(project_target["id"], "main")
        self.store.update_job(
            passed["id"],
            status="succeeded",
            report={"quality_gate": "OK"},
        )
        self.store.update_job(
            failed["id"],
            status="failed",
            report={"quality_gate": "ERROR"},
        )
        self.store.update_job(active["id"], status="running")

        self.assertEqual(
            self.store.dashboard_summary(),
            {
                "servers": 1,
                "project_targets": 1,
                "presets": 1,
                "schedules": 1,
                "scans": 3,
                "succeeded": 1,
                "failed": 1,
                "active": 1,
                "quality_gate_passed": 1,
                "quality_gate_failed": 1,
            },
        )
        self.assertEqual(
            [job["id"] for job in self.store.list_jobs(label="release")],
            [passed["id"]],
        )
        self.assertEqual(
            [job["id"] for job in self.store.list_jobs(status="failed")],
            [failed["id"]],
        )
        self.assertEqual(
            [job["id"] for job in self.store.list_jobs(result_status="passed")],
            [passed["id"]],
        )
        self.assertEqual(
            [job["id"] for job in self.store.list_jobs(result_status="failed")],
            [failed["id"]],
        )
        self.assertEqual(
            [job["id"] for job in self.store.list_jobs(result_status="pending")],
            [active["id"]],
        )
        self.assertEqual(len(self.store.list_jobs(project_key="repo-key")), 3)
        self.assertEqual(
            len(self.store.list_jobs(project_target_id=project_target["id"])), 3
        )
        self.assertEqual(
            [
                job["id"]
                for job in self.store.list_jobs(
                    trigger_source="schedule",
                    project_key="repo-key",
                    project_target_id=project_target["id"],
                    label="nightly",
                    status="failed",
                    result_status="failed",
                )
            ],
            [failed["id"]],
        )

    def test_due_schedule_claim_is_safe_across_workers(self):
        server = self.store.add_server("Sonar", "https://sonar.example.com", "token")
        project_target = self.store.add_project_target(
            name="Repo",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="repo-key",
            scan_path="",
        )
        self.store.add_schedule(
            name="Nightly",
            project_target_id=project_target["id"],
            branch="main",
            label="",
            cron_expression="0 * * * *",
            next_run_at="2026-08-31T00:00:00+00:00",
        )
        second_worker = ScankeepStore(self.database, self.key)

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(
                executor.map(
                    lambda store: store.claim_due_schedules(
                        "2026-08-31T01:00:00+00:00"
                    ),
                    (self.store, second_worker),
                )
            )

        self.assertEqual(sum(len(claim) for claim in claims), 1)

    def test_existing_database_is_migrated(self):
        database = Path(self.temp_dir.name) / "legacy.db"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE sonar_servers (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                    url TEXT NOT NULL, token TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE repositories (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                    provider TEXT NOT NULL, url TEXT NOT NULL, token TEXT NOT NULL,
                    sonar_server_id TEXT NOT NULL REFERENCES sonar_servers(id),
                    project_key TEXT NOT NULL, scan_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE scan_jobs (
                    id TEXT PRIMARY KEY,
                    repository_id TEXT NOT NULL REFERENCES repositories(id),
                    branch TEXT NOT NULL, status TEXT NOT NULL, phase TEXT NOT NULL,
                    progress INTEGER NOT NULL, worker_pid INTEGER NOT NULL DEFAULT 0,
                    commit_sha TEXT NOT NULL DEFAULT '', report TEXT,
                    error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
                    started_at TEXT, finished_at TEXT
                );
                CREATE TABLE scan_presets (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                    repository_id TEXT NOT NULL REFERENCES repositories(id),
                    branch TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                INSERT INTO sonar_servers
                    (id, name, url, token, created_at)
                VALUES
                    ('server-id', 'Existing', 'https://sonar.example.com',
                     'encrypted-token', '2026-08-28T00:00:00+00:00');
                INSERT INTO repositories
                    (id, name, provider, url, token, sonar_server_id,
                     project_key, scan_path, created_at)
                VALUES
                    ('repository-id', 'Existing repo', 'github',
                     'https://github.com/example/repo.git', 'encrypted-token',
                     'server-id', 'existing-key', '',
                     '2026-08-28T00:00:00+00:00');
                INSERT INTO scan_jobs
                    (id, repository_id, branch, status, phase, progress, created_at)
                VALUES
                    ('job-id', 'repository-id', 'main', 'succeeded',
                     'Completed', 100, '2026-08-28T01:00:00+00:00');
                INSERT INTO scan_presets
                    (id, name, repository_id, branch, label, created_at)
                VALUES
                    ('preset-id', 'Existing preset', 'repository-id', 'main',
                     '', '2026-08-28T00:30:00+00:00');
                """
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            migrated = next(
                executor.map(
                    lambda _: ScankeepStore(database, self.key),
                    range(2),
                )
            )

        with closing(sqlite3.connect(database)) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(scan_jobs)")
            }
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            project_target_columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(project_targets)")
            }
            preset_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(scan_presets)")
            }
        self.assertTrue(
            {
                "label",
                "preset_id",
                "preset_name",
                "schedule_id",
                "schedule_name",
                "trigger_source",
            }
            <= columns
        )
        self.assertIn("scan_presets", tables)
        self.assertIn("scan_schedules", tables)
        self.assertIn("security_servers", tables)
        self.assertIn("project_targets", tables)
        self.assertNotIn("sonar_servers", tables)
        self.assertNotIn("repositories", tables)
        self.assertIn("project_target_id", columns)
        self.assertNotIn("repository_id", columns)
        self.assertIn("project_target_id", preset_columns)
        self.assertNotIn("repository_id", preset_columns)
        self.assertIn("security_server_id", project_target_columns)
        self.assertNotIn("sonar_server_id", project_target_columns)
        self.assertEqual(migrated.list_servers()[0]["name"], "Existing")
        self.assertEqual(migrated.list_project_targets()[0]["name"], "Existing repo")
        self.assertEqual(
            migrated.get_job("job-id")["project_target_id"], "repository-id"
        )
        self.assertEqual(
            migrated.get_preset("preset-id")["project_target_name"], "Existing repo"
        )

    def test_interval_schedule_is_migrated_to_cron(self):
        database = Path(self.temp_dir.name) / "interval.db"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.executescript(
                """
                    CREATE TABLE security_servers (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                        url TEXT NOT NULL, token TEXT NOT NULL, created_at TEXT NOT NULL
                    );
                    CREATE TABLE repositories (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                        provider TEXT NOT NULL, url TEXT NOT NULL, token TEXT NOT NULL,
                        security_server_id TEXT NOT NULL REFERENCES security_servers(id),
                        project_key TEXT NOT NULL, scan_path TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE scan_schedules (
                        id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                        repository_id TEXT NOT NULL REFERENCES repositories(id),
                        branch TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
                        interval_minutes INTEGER NOT NULL, enabled INTEGER NOT NULL,
                        next_run_at TEXT NOT NULL, last_run_at TEXT,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    INSERT INTO security_servers VALUES (
                        'server', 'Sonar', 'https://sonar.example.com', 'token', 'now'
                    );
                    INSERT INTO repositories VALUES (
                        'repo', 'Repo', 'github', 'https://github.com/o/r.git',
                        'token', 'server', 'key', '', 'now'
                    );
                    INSERT INTO scan_schedules VALUES (
                        'schedule', 'Hourly', 'repo', 'main', '', 60, 1,
                        '2026-09-01T01:00:00+00:00', NULL, 'now', 'now'
                    );
                """
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            migrated = next(
                executor.map(
                    lambda _: ScankeepStore(database, self.key),
                    range(2),
                )
            )
        schedule = migrated.get_schedule("schedule")
        with closing(sqlite3.connect(database)) as connection:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(scan_schedules)")
            }

        self.assertEqual(schedule["cron_expression"], "0 */1 * * *")
        self.assertTrue(schedule["enabled"])
        self.assertIn("project_target_id", columns)
        self.assertNotIn("repository_id", columns)
        self.assertNotIn("interval_minutes", columns)


class ConnectionTests(unittest.TestCase):
    def test_normalizes_repository_and_scan_path(self):
        self.assertEqual(
            connections.normalize_repository_url(
                "https://github.com/example/repo", "github"
            ),
            "https://github.com/example/repo.git",
        )
        self.assertEqual(
            connections.normalize_repository_url(
                "https://gitlab.example.com:8443/group/repo", "gitlab"
            ),
            "https://gitlab.example.com:8443/group/repo.git",
        )
        self.assertEqual(
            connections.normalize_scan_path("services/agent/"), "services/agent"
        )
        with self.assertRaises(ValueError):
            connections.normalize_scan_path("../secret")
        with self.assertRaises(ValueError):
            connections.normalize_repository_url(
                "https://gitlab.example.com/group/repo", "github"
            )

    def test_git_token_is_passed_by_environment_not_url(self):
        with mock.patch.dict(
            os.environ,
            {
                "SCANKEEP_ACCESS_TOKEN": "access-secret",
                "SCANKEEP_ACCESS_TOKEN_FILE": "/run/secrets/access",
                "SCANKEEP_ENCRYPTION_KEY": "encryption-secret",
                "SCANKEEP_ENCRYPTION_KEY_FILE": "/run/secrets/encryption",
            },
        ):
            env = connections.git_environment("gitlab", "private-token")
        self.assertIn("Authorization: Basic", env["GIT_CONFIG_VALUE_0"])
        self.assertNotIn("private-token", env["GIT_CONFIG_VALUE_0"])
        self.assertNotIn("SCANKEEP_ACCESS_TOKEN", env)
        self.assertNotIn("SCANKEEP_ACCESS_TOKEN_FILE", env)
        self.assertNotIn("SCANKEEP_ENCRYPTION_KEY", env)
        self.assertNotIn("SCANKEEP_ENCRYPTION_KEY_FILE", env)

    @mock.patch("scankeep.connections.subprocess.run")
    def test_lists_remote_branches(self, run):
        run.return_value = SimpleNamespace(
            returncode=0,
            stdout=(
                "abc\trefs/heads/main\ndef\trefs/heads/release/1.0\nghi\trefs/tags/v1\n"
            ),
            stderr="",
        )

        branches = connections.list_remote_branches(
            "https://gitlab.example.com/group/repo.git",
            "gitlab",
            "token",
        )

        self.assertEqual(branches, ["main", "release/1.0"])
        command = run.call_args.args[0]
        self.assertNotIn("token", " ".join(command))

    @mock.patch("scankeep.connections.httpx.get")
    def test_fetches_quality_gate_and_measure_report(self, get):
        def response(payload):
            item = mock.Mock()
            item.raise_for_status.return_value = None
            item.json.return_value = payload
            return item

        get.side_effect = [
            response({"projectStatus": {"status": "OK"}}),
            response(
                {
                    "component": {
                        "measures": [
                            {"metric": "coverage", "value": "91.5"},
                            {"metric": "bugs", "value": "0"},
                        ]
                    }
                }
            ),
            response(
                {
                    "analyses": [
                        {
                            "date": "2026-08-26T01:00:00+0000",
                            "revision": "abc123",
                        }
                    ]
                }
            ),
        ]

        report = connections.fetch_sonar_report(
            "https://sonar.example.com",
            "token",
            "service-key",
            "develop",
            expected_revision="abc123",
        )

        self.assertEqual(report["quality_gate"], "OK")
        self.assertEqual(report["analysis_revision"], "abc123")
        self.assertEqual(report["measures"]["coverage"], "91.5")
        self.assertIn("branch=develop", report["dashboard_url"])

    @mock.patch("scankeep.connections.httpx.get")
    def test_report_rejects_a_previous_commit(self, get):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        response.json.side_effect = [
            {"projectStatus": {"status": "ERROR"}},
            {"component": {"measures": []}},
            {"analyses": [{"revision": "previous"}]},
        ]
        get.side_effect = [response, response, response]

        with self.assertRaisesRegex(connections.ConnectionError, "scanned commit"):
            connections.fetch_sonar_report(
                "https://sonar.example.com",
                "token",
                "service-key",
                "develop",
                expected_revision="current",
            )

    @mock.patch("scankeep.connections.httpx.get")
    def test_checks_sonar_server_health(self, get):
        status_response = mock.Mock()
        status_response.raise_for_status.return_value = None
        status_response.json.return_value = {"status": "UP", "version": "2026.1"}
        auth_response = mock.Mock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"valid": True}
        get.side_effect = [status_response, auth_response]

        health = connections.check_sonar_server_health(
            "https://sonar.example.com", "token"
        )

        self.assertTrue(health["healthy"])
        self.assertEqual(health["status"], "UP")
        self.assertEqual(health["version"], "2026.1")

    @mock.patch("scankeep.connections.httpx.get")
    def test_health_rejects_expired_server_token(self, get):
        status_response = mock.Mock()
        status_response.raise_for_status.return_value = None
        status_response.json.return_value = {"status": "UP", "version": "2026.1"}
        auth_response = mock.Mock()
        auth_response.raise_for_status.return_value = None
        auth_response.json.return_value = {"valid": False}
        get.side_effect = [status_response, auth_response]

        health = connections.check_sonar_server_health(
            "https://sonar.example.com", "expired-token"
        )

        self.assertFalse(health["healthy"])
        self.assertEqual(health["status"], "AUTHENTICATION_FAILED")


class CronTests(unittest.TestCase):
    def test_validates_and_evaluates_five_field_cron_in_utc(self):
        expression = cron.normalize_cron("  0   2  * * 1-5 ")

        self.assertEqual(expression, "0 2 * * 1-5")
        self.assertEqual(
            cron.next_cron_run(expression, "2026-08-31T03:00:00+00:00"),
            "2026-09-01T02:00:00+00:00",
        )
        self.assertEqual(
            cron.next_cron_run(expression, "2026-08-31T10:00:00+07:00"),
            "2026-09-01T02:00:00+00:00",
        )

    def test_cron_ignores_the_host_timezone(self):
        if not hasattr(time, "tzset"):
            self.skipTest("host timezone cannot be changed on this platform")
        runs = []
        try:
            for zone in ("Asia/Ho_Chi_Minh", "America/Los_Angeles"):
                with mock.patch.dict(os.environ, {"TZ": zone}):
                    time.tzset()
                    runs.append(
                        cron.next_cron_run("0 2 * * *", "2026-08-31T19:00:00+00:00")
                    )
        finally:
            time.tzset()

        self.assertEqual(runs, ["2026-09-01T02:00:00+00:00"] * 2)

    def test_rejects_invalid_or_nonstandard_cron(self):
        for expression in ("not cron", "0 0 0 * * *", "61 * * * *"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                cron.normalize_cron(expression)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.store = ScankeepStore(
            self.root / "scankeep.db", Fernet.generate_key().decode()
        )
        server = self.store.add_server(
            "Sonar", "https://sonar.example.com", "sonar-token"
        )
        self.project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="services/agent",
        )
        self.runner = ScanRunner(self.store, self.root)

    def tearDown(self):
        self.runner.executor.shutdown(wait=True)
        self.temp_dir.cleanup()

    @mock.patch("scankeep.runner.os.killpg", side_effect=ProcessLookupError)
    @mock.patch("scankeep.runner.subprocess.Popen")
    def test_timeout_handles_process_exit_before_group_kill(self, popen, _killpg):
        process = popen.return_value
        process.pid = 123
        process.wait.side_effect = [
            subprocess.TimeoutExpired("sonar-scanner", 1),
            0,
        ]

        with self.assertRaisesRegex(ScanError, "timed out"):
            self.runner._run_command(
                ["sonar-scanner", "--version"],
                io.StringIO(),
                timeout=1,
            )

    def test_successful_scan_tracks_commit_and_report(self):
        job = self.store.create_job(self.project_target["id"], "develop")
        commands = []
        command_options = []

        def fake_command(command, log, **kwargs):
            commands.append(command)
            command_options.append(kwargs)
            if command[0] == "git":
                checkout = Path(command[-1])
                (checkout / "services" / "agent").mkdir(parents=True)
            log.write("command output\n")

        report = {
            "quality_gate": "OK",
            "measures": {"coverage": "88.2"},
            "analysis_date": "2026-08-26T01:00:00+0000",
            "dashboard_url": "https://sonar.example.com/dashboard?id=agent-key",
        }
        with (
            mock.patch.object(self.runner, "_run_command", side_effect=fake_command),
            mock.patch(
                "scankeep.runner.subprocess.run",
                return_value=SimpleNamespace(stdout="abc123\n", returncode=0),
            ),
            mock.patch("scankeep.runner.fetch_sonar_report", return_value=report),
        ):
            self.runner._execute(job["id"])

        completed = self.store.get_job(job["id"])
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(completed["commit_sha"], "abc123")
        self.assertEqual(completed["report"]["quality_gate"], "OK")
        self.assertNotIn("--depth", commands[0])
        self.assertIn("--branch", commands[0])
        scanner = commands[1]
        self.assertEqual(scanner[0], "sonar-scanner")
        self.assertIn("-Dsonar.projectKey=agent-key", scanner)
        self.assertIn("-Dsonar.branch.name=develop", scanner)
        self.assertNotIn("sonar-token", scanner)
        self.assertEqual(
            command_options[1]["cwd"].parts[-3:],
            ("source", "services", "agent"),
        )
        self.assertEqual(
            command_options[1]["env"]["SONAR_USER_HOME"],
            str(self.runner.cache_dir),
        )
        self.assertNotIn("git-token", commands[0])

    def test_failed_quality_gate_is_a_completed_execution(self):
        job = self.store.create_job(self.project_target["id"], "develop")

        def fake_command(command, log, **_kwargs):
            if command[0] == "git":
                (Path(command[-1]) / "services" / "agent").mkdir(parents=True)
                return
            raise ScanError("sonar-scanner exited with status 2")

        report = {
            "quality_gate": "ERROR",
            "measures": {"coverage": "60"},
            "analysis_date": "2026-08-31T01:00:00+0000",
            "analysis_revision": "abc123",
            "dashboard_url": "https://sonar.example.com/dashboard?id=agent-key",
        }
        with (
            mock.patch.object(self.runner, "_run_command", side_effect=fake_command),
            mock.patch(
                "scankeep.runner.subprocess.run",
                return_value=SimpleNamespace(stdout="abc123\n", returncode=0),
            ),
            mock.patch(
                "scankeep.runner.fetch_sonar_report", return_value=report
            ) as fetch,
        ):
            self.runner._execute(job["id"])

        completed = self.store.get_job(job["id"])
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(completed["report"]["quality_gate"], "ERROR")
        self.assertEqual(fetch.call_args.kwargs["expected_revision"], "abc123")

    def test_scanner_error_is_not_hidden_by_a_passing_report(self):
        job = self.store.create_job(self.project_target["id"], "develop")

        def fake_command(command, log, **_kwargs):
            if command[0] == "git":
                (Path(command[-1]) / "services" / "agent").mkdir(parents=True)
                return
            raise ScanError("sonar-scanner exited with status 1")

        report = {
            "quality_gate": "OK",
            "measures": {},
            "analysis_date": "2026-08-31T01:00:00+0000",
            "analysis_revision": "abc123",
            "dashboard_url": "https://sonar.example.com/dashboard?id=agent-key",
        }
        with (
            mock.patch.object(self.runner, "_run_command", side_effect=fake_command),
            mock.patch(
                "scankeep.runner.subprocess.run",
                return_value=SimpleNamespace(stdout="abc123\n", returncode=0),
            ),
            mock.patch("scankeep.runner.fetch_sonar_report", return_value=report),
        ):
            self.runner._execute(job["id"])

        failed = self.store.get_job(job["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["report"]["quality_gate"], "OK")
        self.assertIn("sonar-scanner exited", failed["error"])

    def test_orphaned_scan_is_marked_failed(self):
        job = self.store.create_job(self.project_target["id"], "develop")
        self.store.update_job(job["id"], status="running", worker_pid=999_999_999)

        reconciled = self.runner.get_job(job["id"])

        self.assertEqual(reconciled["status"], "failed")
        self.assertIn("worker stopped", reconciled["error"])

    def test_credential_error_marks_job_failed(self):
        job = self.store.create_job(self.project_target["id"], "develop")
        self.store._cipher = Fernet(Fernet.generate_key())

        self.runner._execute(job["id"])

        failed = self.store.get_job(job["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertIn("cannot be decrypted", failed["error"])


class SchedulerTests(unittest.TestCase):
    def test_due_schedule_starts_one_tagged_job(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScankeepStore(
                Path(temp_dir) / "scankeep.db", Fernet.generate_key().decode()
            )
            server = store.add_server("Sonar", "https://sonar.example.com", "token")
            project_target = store.add_project_target(
                name="Repo",
                provider="github",
                url="https://github.com/example/repo.git",
                token="git-token",
                security_server_id=server["id"],
                project_key="repo-key",
                scan_path="",
            )
            schedule = store.add_schedule(
                name="Frequent",
                project_target_id=project_target["id"],
                branch="main",
                label="Scheduled check",
                cron_expression="*/5 * * * *",
                next_run_at="2020-01-01T00:00:00+00:00",
            )
            runner = mock.Mock()
            runner.list_jobs.return_value = []
            scheduler = ScanScheduler(store, runner)

            scheduler.run_due()
            scheduler.run_due()

            runner.start.assert_called_once_with(
                project_target["id"],
                "main",
                label="Scheduled check",
                schedule_id=schedule["id"],
                schedule_name="Frequent",
                trigger_source="schedule",
            )

    def test_active_scheduled_scan_prevents_overlap(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ScankeepStore(
                Path(temp_dir) / "scankeep.db", Fernet.generate_key().decode()
            )
            server = store.add_server("Sonar", "https://sonar.example.com", "token")
            project_target = store.add_project_target(
                name="Repo",
                provider="github",
                url="https://github.com/example/repo.git",
                token="git-token",
                security_server_id=server["id"],
                project_key="repo-key",
                scan_path="",
            )
            schedule = store.add_schedule(
                name="Frequent",
                project_target_id=project_target["id"],
                branch="main",
                label="",
                cron_expression="*/5 * * * *",
                next_run_at="2020-01-01T00:00:00+00:00",
            )
            job = store.create_job(
                project_target["id"],
                "main",
                schedule_id=schedule["id"],
                schedule_name=schedule["name"],
                trigger_source="schedule",
            )
            store.update_job(job["id"], status="running")
            runner = mock.Mock()
            runner.list_jobs.return_value = [{"status": "running"}]

            ScanScheduler(store, runner).run_due()

            runner.start.assert_not_called()
            self.assertGreater(
                store.get_schedule(schedule["id"])["next_run_at"],
                "2020-01-01T00:00:00+00:00",
            )


class AppTests(unittest.TestCase):
    def test_standalone_app_reads_secret_files_and_sets_security_headers(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            access_token = root / "access-token"
            encryption_key = root / "encryption-key"
            access_token.write_text("access-secret\n", encoding="utf-8")
            encryption_key.write_text(
                Fernet.generate_key().decode() + "\n",
                encoding="utf-8",
            )
            environment = {
                "SCANKEEP_ACCESS_TOKEN_FILE": str(access_token),
                "SCANKEEP_ENCRYPTION_KEY_FILE": str(encryption_key),
                "SCANKEEP_DATA_DIR": str(root / "data"),
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch("scankeep.ScanScheduler.start"),
            ):
                app = create_app()
                client = app.test_client()
                health = client.get("/healthz")
                api = client.get(
                    "/api/scankeep/config",
                    headers={"Authorization": "Bearer access-secret"},
                )
                page = client.get("/scankeep")
                redirect_response = client.get("/")
                self.assertNotIn("SCANKEEP_ACCESS_TOKEN", os.environ)
                self.assertNotIn("SCANKEEP_ENCRYPTION_KEY", os.environ)
                app.extensions["scankeep_runner"].stop()

        self.assertEqual(health.get_json(), {"status": "ok"})
        self.assertEqual(api.status_code, 200)
        self.assertEqual(redirect_response.location, "/scankeep")
        self.assertEqual(health.headers["X-Frame-Options"], "DENY")
        self.assertEqual(health.headers["Cross-Origin-Resource-Policy"], "same-origin")
        self.assertIn("camera=()", health.headers["Permissions-Policy"])
        self.assertEqual(api.headers["Cache-Control"], "no-store")
        script_policy = next(
            directive.strip()
            for directive in page.headers["Content-Security-Policy"].split(";")
            if directive.strip().startswith("script-src")
        )
        nonce = script_policy.split("'nonce-", 1)[1].split("'", 1)[0]
        self.assertNotIn("unsafe-inline", script_policy)
        self.assertIn(
            f'<script nonce="{nonce}">',
            page.get_data(as_text=True),
        )

    def test_standalone_app_fails_closed_without_secrets(self):
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(RuntimeError, "SCANKEEP_ACCESS_TOKEN"),
        ):
            create_app()


class BootstrapTests(unittest.TestCase):
    def test_initialization_creates_secrets_once_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "secrets"
            output = io.StringIO()
            with redirect_stdout(output):
                bootstrap.initialize(directory)
            access_token = (directory / "access_token").read_text(encoding="utf-8")
            encryption_key = (directory / "encryption_key").read_text(encoding="utf-8")
            (directory / "access_token").chmod(0o644)
            (directory / "encryption_key").chmod(0o644)

            with redirect_stdout(io.StringIO()):
                bootstrap.initialize(directory)

            self.assertIn("Initial access token:", output.getvalue())
            self.assertEqual(
                (directory / "access_token").read_text(encoding="utf-8"),
                access_token,
            )
            self.assertEqual(
                (directory / "encryption_key").read_text(encoding="utf-8"),
                encryption_key,
            )
            self.assertEqual((directory / "access_token").stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (directory / "encryption_key").stat().st_mode & 0o777,
                0o600,
            )
            Fernet(encryption_key.strip().encode())

    def test_initialization_rejects_incomplete_existing_secrets(self):
        for existing_name, missing_name in (
            ("access_token", "encryption_key"),
            ("encryption_key", "access_token"),
        ):
            with (
                self.subTest(existing_name=existing_name),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                directory = Path(temp_dir)
                existing_path = directory / existing_name
                existing_path.write_text("existing-secret\n", encoding="utf-8")

                with self.assertRaisesRegex(SystemExit, "secrets are incomplete"):
                    bootstrap.initialize(directory)

                self.assertFalse((directory / missing_name).exists())
                self.assertEqual(
                    existing_path.read_text(encoding="utf-8"),
                    "existing-secret\n",
                )

    def test_show_access_token_rejects_missing_or_empty_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            with self.assertRaisesRegex(SystemExit, "cannot read access token"):
                bootstrap.show_access_token(directory)
            (directory / "access_token").touch()
            with self.assertRaisesRegex(SystemExit, "access token is empty"):
                bootstrap.show_access_token(directory)

    def test_access_token_rotation_preserves_encryption_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir) / "secrets"
            with redirect_stdout(io.StringIO()):
                bootstrap.initialize(directory)
            old_access_token = (directory / "access_token").read_text(encoding="utf-8")
            encryption_key = (directory / "encryption_key").read_text(encoding="utf-8")
            output = io.StringIO()

            with redirect_stdout(output):
                bootstrap.rotate_access_token(directory)

            self.assertNotEqual(
                (directory / "access_token").read_text(encoding="utf-8"),
                old_access_token,
            )
            self.assertEqual(
                (directory / "encryption_key").read_text(encoding="utf-8"),
                encryption_key,
            )
            self.assertIn("New access token:", output.getvalue())

    def test_access_token_rotation_requires_valid_encryption_key(self):
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            self.assertRaisesRegex(SystemExit, "valid encryption key"),
        ):
            bootstrap.rotate_access_token(Path(temp_dir))


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = ScankeepStore(
            Path(self.temp_dir.name) / "scankeep.db",
            Fernet.generate_key().decode(),
        )
        self.runner = mock.Mock()
        self.runner.runtime_status.return_value = {
            "git": True,
            "sonar_scanner": True,
        }
        self.runner.list_jobs.return_value = []
        self.app = Flask(__name__)
        self.app.config["SCANKEEP_ACCESS_TOKEN"] = "access-secret"
        self.app.extensions["scankeep_store"] = self.store
        self.app.extensions["scankeep_runner"] = self.runner
        self.app.register_blueprint(routes.scankeep_bp)
        self.client = self.app.test_client()
        self.headers = {"Authorization": "Bearer access-secret"}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_api_requires_access_token(self):
        response = self.client.get("/api/scankeep/servers")
        self.assertEqual(response.status_code, 401)

    def test_multi_page_routes_render(self):
        for path in (
            "/scankeep",
            "/scankeep/manual-scans",
            "/scankeep/jobs/job-id",
            "/scankeep/presets",
            "/scankeep/presets/new",
            "/scankeep/presets/preset-id",
            "/scankeep/schedules",
            "/scankeep/schedules/new",
            "/scankeep/schedules/schedule-id",
            "/scankeep/servers",
            "/scankeep/servers/new",
            "/scankeep/servers/server-id",
            "/scankeep/project-targets",
            "/scankeep/project-targets/new",
            "/scankeep/project-targets/project-target-id",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 200)
        static_response = self.client.get("/scankeep/static/scankeep.css")
        self.assertEqual(static_response.status_code, 200)
        static_response.close()

    def test_retired_routes_are_not_retained(self):
        for path in (
            "/scankeep/repositories",
            "/api/scankeep/repositories",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)

    def test_pages_load_access_gate_script_before_body(self):
        for path in (
            "/scankeep",
            "/scankeep/manual-scans",
            "/scankeep/jobs/job-id",
            "/scankeep/presets",
            "/scankeep/presets/new",
            "/scankeep/presets/preset-id",
            "/scankeep/schedules",
            "/scankeep/schedules/new",
            "/scankeep/schedules/schedule-id",
            "/scankeep/servers",
            "/scankeep/servers/new",
            "/scankeep/servers/server-id",
            "/scankeep/project-targets",
            "/scankeep/project-targets/new",
            "/scankeep/project-targets/project-target-id",
        ):
            with self.subTest(path=path):
                markup = self.client.get(path).get_data(as_text=True)
                head = markup[: markup.index("<body")]

                self.assertIn("scankeep.js", head)
                self.assertIn('<div id="app">', markup)

    def test_home_dashboard_returns_summary(self):
        self.store.add_server("Production", "https://sonar.example.com", "sonar-token")

        response = self.client.get("/api/scankeep/dashboard", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["servers"], 1)
        self.assertEqual(response.get_json()["scans"], 0)

    def test_home_and_manual_scans_are_separate_and_navigation_is_ordered(self):
        home = self.client.get("/scankeep").get_data(as_text=True)
        manual = self.client.get("/scankeep/manual-scans").get_data(as_text=True)
        navigation = home[home.index("<nav>") : home.index("</nav>")]

        self.assertIn("Security scanning overview", home)
        self.assertIn('summaryCard("Scheduled scans", stats.schedules', home)
        self.assertNotIn('summaryCard("Automation"', home)
        self.assertNotIn('summaryCard("Scan presets"', home)
        self.assertNotIn('id="scan-form"', home)
        self.assertIn('id="scan-form"', manual)
        self.assertIn(">Home</a>", navigation)
        self.assertIn("/scankeep/manual-scans", navigation)
        self.assertLess(
            navigation.index(">Project targets</a>"),
            navigation.index(">Security servers</a>"),
        )

    def test_schedule_detail_exposes_full_editing_and_run_now(self):
        markup = self.client.get("/scankeep/schedules/schedule-id").get_data(
            as_text=True
        )

        for field in (
            'name="name"',
            'name="cron_expression"',
            'name="security_server_id"',
            'name="project_target_id"',
            'name="project_key"',
            'name="branch"',
            'name="label"',
            'id="run-schedule"',
        ):
            with self.subTest(field=field):
                self.assertIn(field, markup)

    def test_scan_forms_auto_load_branches_and_histories_can_refresh(self):
        response = self.client.get("/scankeep/static/scankeep.js")
        script = response.get_data(as_text=True)
        response.close()
        self.assertIn("await loadBranches(initial.branch)", script)
        self.assertIn(
            'element("project-target-select").addEventListener("change"', script
        )

        for path in (
            "/scankeep/manual-scans",
            "/scankeep/presets/new",
            "/scankeep/presets/preset-id",
            "/scankeep/schedules/new",
            "/scankeep/schedules/schedule-id",
        ):
            with self.subTest(path=path):
                markup = self.client.get(path).get_data(as_text=True)
                self.assertIn('id="branch-select"', markup)
                self.assertNotIn('id="load-branches"', markup)

        history_pages = {
            "/scankeep": "Scankeep.createScanFilters()",
            "/scankeep/manual-scans": 'trigger_source: "manual"',
            "/scankeep/presets/preset-id": "preset_id: presetId",
            "/scankeep/schedules/schedule-id": "schedule_id: scheduleId",
        }
        for path, fixed_filter in history_pages.items():
            with self.subTest(path=path):
                markup = self.client.get(path).get_data(as_text=True)
                self.assertIn('id="refresh-runs"', markup)
                self.assertIn('id="scan-filters"', markup)
                self.assertIn("filters.scansPath()", markup)
                self.assertIn(fixed_filter, markup)
                for field in (
                    "project_key",
                    "label",
                    "project_target_id",
                    "status",
                    "result_status",
                ):
                    self.assertIn(f'name="{field}"', markup)

        home = self.client.get("/scankeep").get_data(as_text=True)
        self.assertIn('name="trigger_source"', home)

    def test_inventory_tables_sort_every_column(self):
        expected_columns = {
            "/scankeep/presets": (
                "name",
                "target",
                "server",
                "branch",
                "label",
                "created",
            ),
            "/scankeep/schedules": (
                "name",
                "target",
                "server",
                "branch",
                "cron",
                "status",
                "next",
                "last",
            ),
            "/scankeep/project-targets": (
                "name",
                "provider",
                "url",
                "server",
                "project",
                "path",
                "created",
            ),
            "/scankeep/servers": (
                "name",
                "url",
                "status",
                "version",
                "latency",
                "checked",
                "created",
            ),
        }

        for path, columns in expected_columns.items():
            with self.subTest(path=path):
                markup = self.client.get(path).get_data(as_text=True)
                self.assertEqual(markup.count('aria-sort="none"'), len(columns))
                self.assertEqual(markup.count('class="sort-button"'), len(columns))
                self.assertIn("Scankeep.createSortableTable(", markup)
                for column in columns:
                    self.assertIn(f'data-sort="{column}"', markup)
                    self.assertIn(f"\n    {column}:", markup)

    def test_delete_preserves_dependent_scan_history(self):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="",
        )
        self.store.create_job(project_target["id"], "main")

        project_target_response = self.client.delete(
            f"/api/scankeep/project-targets/{project_target['id']}",
            headers=self.headers,
        )
        server_response = self.client.delete(
            f"/api/scankeep/servers/{server['id']}",
            headers=self.headers,
        )

        self.assertEqual(project_target_response.status_code, 409)
        self.assertEqual(server_response.status_code, 409)

    @mock.patch("scankeep.routes.validate_sonar_server")
    @mock.patch(
        "scankeep.routes.list_remote_branches",
        return_value=["develop", "main"],
    )
    def test_add_connections_list_branches_and_start_scan(self, _branches, _validate):
        server_response = self.client.post(
            "/api/scankeep/servers",
            headers=self.headers,
            json={
                "name": "Production",
                "url": "https://sonar.example.com",
                "token": "sonar-token",
            },
        )
        self.assertEqual(server_response.status_code, 201)
        server_id = server_response.get_json()["id"]

        project_target_response = self.client.post(
            "/api/scankeep/project-targets",
            headers=self.headers,
            json={
                "name": "Agent",
                "provider": "github",
                "url": "https://github.com/example/repo",
                "token": "git-token",
                "security_server_id": server_id,
                "project_key": "agent-key",
                "scan_path": "services/agent",
            },
        )
        self.assertEqual(project_target_response.status_code, 201)
        project_target_id = project_target_response.get_json()["id"]

        branch_response = self.client.get(
            f"/api/scankeep/project-targets/{project_target_id}/branches",
            headers=self.headers,
        )
        self.assertEqual(branch_response.get_json()["branches"], ["develop", "main"])

        self.runner.start.return_value = {
            "id": "job-id",
            "project_target_id": project_target_id,
            "branch": "develop",
            "status": "queued",
        }
        scan_response = self.client.post(
            "/api/scankeep/scans",
            headers=self.headers,
            json={
                "project_target_id": project_target_id,
                "security_server_id": server_id,
                "project_key": "agent-key",
                "branch": "develop",
                "label": "Manual validation",
            },
        )
        self.assertEqual(scan_response.status_code, 202)
        self.runner.start.assert_called_once_with(
            project_target_id,
            "develop",
            label="Manual validation",
            preset_id=None,
            preset_name="",
            schedule_id=None,
            schedule_name="",
            trigger_source="manual",
        )

    @mock.patch(
        "scankeep.routes.check_sonar_server_health",
        return_value={
            "healthy": True,
            "status": "UP",
            "version": "2026.1",
            "latency_ms": 5,
            "error": "",
        },
    )
    def test_server_health_endpoint(self, _health):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )

        response = self.client.get("/api/scankeep/servers/health", headers=self.headers)
        detail_response = self.client.get(
            f"/api/scankeep/servers/{server['id']}/health",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(detail_response.status_code, 200)
        result = response.get_json()["servers"][0]
        self.assertEqual(result["id"], server["id"])
        self.assertTrue(result["healthy"])
        self.assertIn("checked_at", result)

    @mock.patch("scankeep.routes.validate_sonar_server")
    @mock.patch(
        "scankeep.routes.list_remote_branches",
        return_value=["main"],
    )
    def test_rotates_connection_tokens(self, _branches, _validate):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "old-sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="old-git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="",
        )

        server_response = self.client.patch(
            f"/api/scankeep/servers/{server['id']}",
            headers=self.headers,
            json={"token": "new-sonar-token"},
        )
        project_target_response = self.client.patch(
            f"/api/scankeep/project-targets/{project_target['id']}",
            headers=self.headers,
            json={"token": "new-git-token"},
        )

        self.assertEqual(server_response.status_code, 200)
        self.assertEqual(project_target_response.status_code, 200)
        self.assertEqual(
            self.store.get_server(server["id"], include_token=True)["token"],
            "new-sonar-token",
        )
        self.assertEqual(
            self.store.get_project_target(project_target["id"], include_tokens=True)[
                "token"
            ],
            "new-git-token",
        )

    @mock.patch("scankeep.routes.validate_sonar_server")
    @mock.patch(
        "scankeep.routes.list_remote_branches",
        return_value=["main"],
    )
    def test_edits_connections_without_replacing_tokens(self, _branches, _validate):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="",
        )

        server_response = self.client.patch(
            f"/api/scankeep/servers/{server['id']}",
            headers=self.headers,
            json={
                "name": "Primary",
                "url": "https://sonar.example.com/",
                "token": "",
            },
        )
        project_target_response = self.client.patch(
            f"/api/scankeep/project-targets/{project_target['id']}",
            headers=self.headers,
            json={
                "name": "Agent service",
                "provider": "github",
                "url": "https://github.com/example/repo",
                "token": "",
                "security_server_id": server["id"],
                "project_key": "agent-new",
                "scan_path": "service",
            },
        )

        self.assertEqual(server_response.status_code, 200)
        self.assertEqual(project_target_response.status_code, 200)
        private_server = self.store.get_server(server["id"], include_token=True)
        private_project_target = self.store.get_project_target(
            project_target["id"], include_tokens=True
        )
        self.assertEqual(private_server["name"], "Primary")
        self.assertEqual(private_server["token"], "sonar-token")
        self.assertEqual(private_project_target["project_key"], "agent-new")
        self.assertEqual(private_project_target["token"], "git-token")

    def test_provider_change_revalidates_existing_repository_url(self):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="",
        )

        response = self.client.patch(
            f"/api/scankeep/project-targets/{project_target['id']}",
            headers=self.headers,
            json={"provider": "gitlab"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("does not match", response.get_json()["error"])

    def test_endpoint_changes_require_replacement_tokens(self):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="",
        )

        server_response = self.client.patch(
            f"/api/scankeep/servers/{server['id']}",
            headers=self.headers,
            json={"url": "https://sonar-new.example.com"},
        )
        project_target_response = self.client.patch(
            f"/api/scankeep/project-targets/{project_target['id']}",
            headers=self.headers,
            json={"url": "https://enterprise.github.com/example/repo"},
        )

        self.assertEqual(server_response.status_code, 400)
        self.assertEqual(project_target_response.status_code, 400)
        self.assertIn("token is required", server_response.get_json()["error"])
        self.assertIn(
            "token is required",
            project_target_response.get_json()["error"],
        )

    @mock.patch(
        "scankeep.routes.list_remote_branches",
        return_value=["develop", "main"],
    )
    def test_create_and_run_preset(self, _branches):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="services/agent",
        )
        create_response = self.client.post(
            "/api/scankeep/presets",
            headers=self.headers,
            json={
                "name": "Agent develop",
                "project_target_id": project_target["id"],
                "branch": "develop",
                "label": "Preset run",
            },
        )
        self.assertEqual(create_response.status_code, 201)
        preset_id = create_response.get_json()["id"]
        update_response = self.client.patch(
            f"/api/scankeep/presets/{preset_id}",
            headers=self.headers,
            json={
                "name": "Agent main",
                "project_target_id": project_target["id"],
                "security_server_id": server["id"],
                "project_key": "agent-key",
                "branch": "main",
                "label": "Updated preset run",
            },
        )
        self.assertEqual(update_response.status_code, 200)
        self.assertEqual(update_response.get_json()["name"], "Agent main")
        self.runner.start.return_value = {"id": "job-id", "status": "queued"}

        run_response = self.client.post(
            f"/api/scankeep/presets/{preset_id}/scans",
            headers=self.headers,
            json={},
        )

        self.assertEqual(run_response.status_code, 202)
        self.runner.start.assert_called_once_with(
            project_target["id"],
            "main",
            label="Updated preset run",
            preset_id=preset_id,
            preset_name="Agent main",
            schedule_id=None,
            schedule_name="",
            trigger_source="preset",
        )

    @mock.patch(
        "scankeep.routes.list_remote_branches",
        return_value=["develop", "main"],
    )
    def test_create_edit_run_pause_and_delete_schedule(self, _branches):
        server = self.store.add_server(
            "Production", "https://sonar.example.com", "sonar-token"
        )
        project_target = self.store.add_project_target(
            name="Agent",
            provider="github",
            url="https://github.com/example/repo.git",
            token="git-token",
            security_server_id=server["id"],
            project_key="agent-key",
            scan_path="",
        )
        created = self.client.post(
            "/api/scankeep/schedules",
            headers=self.headers,
            json={
                "name": "Hourly agent",
                "project_target_id": project_target["id"],
                "branch": "main",
                "label": "Automated",
                "cron_expression": "0 * * * *",
            },
        )
        self.assertEqual(created.status_code, 201)
        schedule = created.get_json()
        self.assertTrue(schedule["enabled"])

        paused = self.client.patch(
            f"/api/scankeep/schedules/{schedule['id']}",
            headers=self.headers,
            json={"enabled": False},
        )
        self.assertEqual(paused.status_code, 200)
        self.assertFalse(paused.get_json()["enabled"])

        updated = self.client.patch(
            f"/api/scankeep/schedules/{schedule['id']}",
            headers=self.headers,
            json={
                "name": "Weekday agent",
                "project_target_id": project_target["id"],
                "security_server_id": server["id"],
                "project_key": "agent-key",
                "branch": "develop",
                "label": "Updated automation",
                "cron_expression": "30 2 * * 1-5",
            },
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["name"], "Weekday agent")
        self.assertEqual(updated.get_json()["branch"], "develop")
        self.assertEqual(updated.get_json()["label"], "Updated automation")
        self.assertEqual(updated.get_json()["cron_expression"], "30 2 * * 1-5")
        self.assertFalse(updated.get_json()["enabled"])
        scheduled_next_run = updated.get_json()["next_run_at"]

        self.runner.start.return_value = {"id": "job-id", "status": "queued"}
        run = self.client.post(
            f"/api/scankeep/schedules/{schedule['id']}/scans",
            headers=self.headers,
            json={},
        )
        self.assertEqual(run.status_code, 202)
        self.runner.start.assert_called_once_with(
            project_target["id"],
            "develop",
            label="Updated automation",
            preset_id=None,
            preset_name="",
            schedule_id=schedule["id"],
            schedule_name="Weekday agent",
            trigger_source="schedule",
        )
        after_run = self.store.get_schedule(schedule["id"])
        self.assertIsNotNone(after_run["last_run_at"])
        self.assertEqual(after_run["next_run_at"], scheduled_next_run)

        invalid = self.client.post(
            "/api/scankeep/schedules",
            headers=self.headers,
            json={
                "name": "Invalid",
                "project_target_id": project_target["id"],
                "branch": "main",
                "cron_expression": "bad cron",
            },
        )
        self.assertEqual(invalid.status_code, 400)

        deleted = self.client.delete(
            f"/api/scankeep/schedules/{schedule['id']}",
            headers=self.headers,
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(self.store.list_schedules(), [])

    def test_scan_history_filters_are_forwarded(self):
        response = self.client.get(
            "/api/scankeep/scans"
            "?trigger_source=schedule&schedule_id=schedule-id"
            "&project_key=agent-key&project_target_id=target-id"
            "&label=release&status=failed&result_status=unavailable",
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.runner.list_jobs.assert_called_once_with(
            trigger_source="schedule",
            preset_id=None,
            schedule_id="schedule-id",
            project_key="agent-key",
            project_target_id="target-id",
            label="release",
            status="failed",
            result_status="unavailable",
        )

    def test_scan_history_rejects_invalid_filters(self):
        for query in (
            "trigger_source=invalid",
            "status=invalid",
            "result_status=invalid",
        ):
            with self.subTest(query=query):
                response = self.client.get(
                    f"/api/scankeep/scans?{query}",
                    headers=self.headers,
                )
                self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
