"""Background scan execution with persisted progress and logs."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import IO

from .connections import (
    ConnectionError,
    fetch_sonar_report,
    git_environment,
    process_environment,
)
from .store import ScankeepStore, utc_now


class ScanError(RuntimeError):
    """A checkout or scanner command failed."""


class ScanRunner:
    def __init__(self, store: ScankeepStore, data_dir: Path) -> None:
        self.store = store
        self.log_dir = data_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.chmod(0o700)
        self.cache_dir = data_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.chmod(0o700)
        workers = max(1, int(os.getenv("SCANKEEP_WORKERS", "2")))
        self.executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="scankeep",
        )

    def stop(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)

    def start(
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
    ) -> dict:
        job = self.store.create_job(
            project_target_id,
            branch,
            label=label,
            preset_id=preset_id,
            preset_name=preset_name,
            schedule_id=schedule_id,
            schedule_name=schedule_name,
            trigger_source=trigger_source,
        )
        self.store.update_job(job["id"], worker_pid=os.getpid())
        try:
            self.executor.submit(self._execute, job["id"])
        except RuntimeError as exc:
            self.store.update_job(
                job["id"],
                status="failed",
                phase="Failed to queue",
                progress=100,
                error=str(exc),
                finished_at=utc_now(),
            )
            raise
        return self.store.get_job(job["id"])

    def get_job(self, job_id: str) -> dict:
        return self._reconcile(self.store.get_job(job_id))

    def list_jobs(
        self,
        *,
        trigger_source: str | None = None,
        preset_id: str | None = None,
        schedule_id: str | None = None,
        project_key: str | None = None,
        project_target_id: str | None = None,
        label: str | None = None,
        status: str | None = None,
        result_status: str | None = None,
    ) -> list[dict]:
        return [
            self._reconcile(job)
            for job in self.store.list_jobs(
                trigger_source=trigger_source,
                preset_id=preset_id,
                schedule_id=schedule_id,
                project_key=project_key,
                project_target_id=project_target_id,
                label=label,
                status=status,
                result_status=result_status,
            )
        ]

    def _reconcile(self, job: dict) -> dict:
        if job["status"] not in {"queued", "running"} or not job["worker_pid"]:
            return job
        try:
            os.kill(job["worker_pid"], 0)
        except ProcessLookupError:
            self.store.update_job(
                job["id"],
                status="failed",
                phase="Interrupted",
                progress=100,
                error="scan worker stopped before completion",
                finished_at=utc_now(),
            )
            return self.store.get_job(job["id"])
        except PermissionError:
            pass
        return job

    def log_path(self, job_id: str) -> Path:
        return self.log_dir / f"{job_id}.log"

    def read_log(self, job_id: str, max_bytes: int = 200_000) -> str:
        path = self.log_path(job_id)
        try:
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                stream.seek(max(0, size - max_bytes))
                return stream.read().decode("utf-8", errors="replace")
        except FileNotFoundError:
            return ""

    def _phase(self, job_id: str, phase: str, progress: int) -> None:
        self.store.update_job(
            job_id,
            status="running",
            phase=phase,
            progress=progress,
        )

    @staticmethod
    def _run_command(
        command: list[str],
        log: IO[str],
        *,
        timeout: int,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> None:
        log.write(f"$ {command[0]} {command[1]}\n")
        log.flush()
        try:
            process = subprocess.Popen(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                cwd=cwd,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            raise ScanError(f"required executable not found: {command[0]}") from exc
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise ScanError(f"{command[0]} timed out after {timeout} seconds") from exc
        if return_code:
            raise ScanError(f"{command[0]} exited with status {return_code}")

    @staticmethod
    def _scan_directory(checkout: Path, scan_path: str) -> Path:
        root = checkout.resolve()
        selected = (root / scan_path).resolve() if scan_path else root
        try:
            selected.relative_to(root)
        except ValueError as exc:
            raise ScanError("scan path resolves outside the repository") from exc
        if not selected.is_dir():
            raise ScanError(
                f"scan path does not exist on the selected branch: {scan_path}"
            )
        return selected

    def _execute(self, job_id: str) -> None:
        job = self.store.get_job(job_id)
        log_path = self.log_path(job_id)
        project_target = None
        scan_attempted = False
        scanner_error = None
        commit_sha = ""
        try:
            project_target = self.store.get_project_target(
                job["project_target_id"], include_tokens=True
            )
            self.store.update_job(job_id, started_at=utc_now())
            with (
                tempfile.TemporaryDirectory(prefix="scankeep-") as temp_dir,
                log_path.open("w", encoding="utf-8") as log,
            ):
                checkout = Path(temp_dir) / "source"
                self._phase(job_id, "Fetching latest branch", 10)
                self._run_command(
                    [
                        "git",
                        "clone",
                        "--single-branch",
                        "--branch",
                        job["branch"],
                        "--",
                        project_target["url"],
                        str(checkout),
                    ],
                    log,
                    timeout=int(os.getenv("SCANKEEP_GIT_TIMEOUT", "600")),
                    env=git_environment(
                        project_target["provider"], project_target["token"]
                    ),
                )
                commit_sha = subprocess.run(
                    ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                    check=True,
                    env=process_environment(),
                ).stdout.strip()
                self.store.update_job(job_id, commit_sha=commit_sha)
                scan_directory = self._scan_directory(
                    checkout, project_target["scan_path"]
                )

                self._phase(job_id, "Running SonarQube scanner", 35)
                scan_attempted = True
                scanner_env = {
                    **process_environment(),
                    "SONAR_HOST_URL": project_target["server_url"],
                    "SONAR_TOKEN": project_target["server_token"],
                    "SONAR_USER_HOME": str(self.cache_dir),
                }
                try:
                    self._run_command(
                        [
                            "sonar-scanner",
                            f"-Dsonar.host.url={project_target['server_url']}",
                            f"-Dsonar.projectKey={project_target['project_key']}",
                            f"-Dsonar.branch.name={job['branch']}",
                            "-Dsonar.analysisCache.enabled=false",
                            "-Dsonar.scanner.socketTimeout=300",
                            "-Dsonar.scanner.responseTimeout=600",
                            "-Dsonar.qualitygate.wait=true",
                            "-Dsonar.qualitygate.timeout=600",
                        ],
                        log,
                        timeout=int(os.getenv("SCANKEEP_SCAN_TIMEOUT", "3600")),
                        env=scanner_env,
                        cwd=scan_directory,
                    )
                except ScanError as exc:
                    scanner_error = exc

            self._phase(job_id, "Loading SonarQube report", 90)
            try:
                report = fetch_sonar_report(
                    project_target["server_url"],
                    project_target["server_token"],
                    project_target["project_key"],
                    job["branch"],
                    expected_revision=commit_sha,
                )
            except ConnectionError:
                if scanner_error:
                    raise scanner_error from None
                raise
            if scanner_error and report["quality_gate"] != "ERROR":
                raise scanner_error
            self.store.update_job(
                job_id,
                status="succeeded",
                phase="Completed",
                progress=100,
                report=report,
                finished_at=utc_now(),
            )
        except Exception as exc:
            report = None
            if scan_attempted and project_target:
                with suppress(ConnectionError):
                    report = fetch_sonar_report(
                        project_target["server_url"],
                        project_target["server_token"],
                        project_target["project_key"],
                        job["branch"],
                        expected_revision=commit_sha,
                    )
            self.store.update_job(
                job_id,
                status="failed",
                phase="Failed",
                progress=100,
                report=report,
                error=str(exc),
                finished_at=utc_now(),
            )

    def runtime_status(self) -> dict[str, bool]:
        return {
            "git": bool(shutil.which("git")),
            "sonar_scanner": bool(shutil.which("sonar-scanner")),
        }

    def ensure_runtime(self) -> None:
        status = self.runtime_status()
        missing = [name for name, ready in status.items() if not ready]
        if missing:
            raise ScanError(
                f"Scankeep host is not ready: {', '.join(missing)} unavailable"
            )
