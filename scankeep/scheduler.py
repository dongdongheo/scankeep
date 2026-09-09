"""Persistent, duplicate-safe scheduled scan triggering."""

from __future__ import annotations

import logging
import os
import threading

from .runner import ScanRunner
from .store import ScankeepStore, utc_now

logger = logging.getLogger(__name__)


class ScanScheduler:
    def __init__(self, store: ScankeepStore, runner: ScanRunner) -> None:
        self.store = store
        self.runner = runner
        self.poll_seconds = max(
            5, int(os.getenv("SCANKEEP_SCHEDULER_POLL_SECONDS", "30"))
        )
        self._stopped = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="scankeep-scheduler",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stopped.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=self.poll_seconds + 1)

    def run_due(self) -> None:
        for schedule in self.store.claim_due_schedules(utc_now()):
            try:
                jobs = self.runner.list_jobs(schedule_id=schedule["id"])
                if any(job["status"] in {"queued", "running"} for job in jobs):
                    continue
                self.runner.start(
                    schedule["project_target_id"],
                    schedule["branch"],
                    label=schedule["label"] or schedule["name"],
                    schedule_id=schedule["id"],
                    schedule_name=schedule["name"],
                    trigger_source="schedule",
                )
            except Exception:
                logger.exception("Failed to process schedule %s", schedule["id"])

    def _run(self) -> None:
        while not self._stopped.is_set():
            try:
                self.run_due()
            except Exception:
                logger.exception("Scheduled scan poll failed")
            self._stopped.wait(self.poll_seconds)
