from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("sakshya.jobs")
STATES = ("queued", "running", "completed", "failed", "cancelled")


class JobCancelled(Exception):
    pass


@dataclass
class JobControl:
    job_id: str
    deadline: float
    manager: JobManager

    def cancelled(self) -> bool:
        return self.manager.is_cancelled(self.job_id) or time.time() > self.deadline

    def check(self) -> None:
        if self.cancelled():
            raise JobCancelled("cancelled" if self.manager.is_cancelled(self.job_id) else "timed out")

    def progress(self, value: float, note: str = "") -> None:
        self.manager.update(self.job_id, progress=round(max(0.0, min(1.0, value)), 3), note=note)


class JobManager:
    def __init__(self, database: Path, workers: int = 2, timeout_s: float = 600.0) -> None:
        self.database = database
        self.timeout_s = timeout_s
        self._pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="sakshya-job")
        self._cancel: set[str] = set()
        self._guard = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _init(self) -> None:
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, case_id TEXT, user_id INTEGER, "
                "status TEXT NOT NULL, progress REAL DEFAULT 0, note TEXT DEFAULT '', created REAL NOT NULL, started REAL, "
                "finished REAL, error TEXT, result TEXT)"
            )
            db.execute(
                "UPDATE jobs SET status='failed', error='Interrupted by a service restart', finished=? "
                "WHERE status IN ('queued','running')",
                (time.time(),),
            )

    def submit(
        self, kind: str, case_id: str | None, user_id: int | None, work: Callable[[JobControl], dict[str, Any] | None]
    ) -> str:
        job_id = uuid.uuid4().hex
        with self._connect() as db:
            db.execute(
                "INSERT INTO jobs (id, kind, case_id, user_id, status, created) VALUES (?,?,?,?,?,?)",
                (job_id, kind, case_id, user_id, "queued", time.time()),
            )
        self._pool.submit(self._run, job_id, work)
        return job_id

    def _run(self, job_id: str, work: Callable[[JobControl], dict[str, Any] | None]) -> None:
        if self.is_cancelled(job_id):
            self.update(job_id, status="cancelled", finished=time.time())
            return
        self.update(job_id, status="running", started=time.time())
        control = JobControl(job_id, time.time() + self.timeout_s, self)
        try:
            result = work(control)
        except JobCancelled as exc:
            self.update(job_id, status="cancelled", finished=time.time(), error=str(exc))
        except Exception as exc:
            logger.warning("Job %s failed: %s", job_id, type(exc).__name__)
            self.update(job_id, status="failed", finished=time.time(), error=_public_error(exc))
        else:
            self.update(job_id, status="completed", finished=time.time(), progress=1.0, result=json.dumps(result or {}))
        finally:
            with self._guard:
                self._cancel.discard(job_id)

    def update(self, job_id: str, **fields: Any) -> None:
        if not fields:
            return
        columns = ", ".join(f"{name}=?" for name in fields)
        with self._connect() as db:
            db.execute(f"UPDATE jobs SET {columns} WHERE id=?", (*fields.values(), job_id))

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["result"] = json.loads(data["result"]) if data.get("result") else None
        return data

    def active_for_case(self, case_id: str, kind: str) -> str | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT id FROM jobs WHERE case_id=? AND kind=? AND status IN ('queued','running') ORDER BY created DESC",
                (case_id, kind),
            ).fetchone()
        return row["id"] if row else None

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None or job["status"] not in {"queued", "running"}:
            return False
        with self._guard:
            self._cancel.add(job_id)
        return True

    def is_cancelled(self, job_id: str) -> bool:
        with self._guard:
            return job_id in self._cancel

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def _public_error(exc: Exception) -> str:
    message = str(exc)
    return message[:400] if getattr(exc, "public", False) else f"{type(exc).__name__}: {message[:300]}"
