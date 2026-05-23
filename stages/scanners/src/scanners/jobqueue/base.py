from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass

from ..models import Target

# Job lifecycle: pending -> running -> {done | failed | skipped}.
#   failed  = transient error, attempts exhausted
#   skipped = permanent, won't be retried (e.g. image too large, manifest gone)
STATUSES = ("pending", "running", "done", "failed", "skipped")


@dataclass
class Job:
    id: int
    target: Target
    attempts: int


class Queue(ABC):
    """A work queue plus a results sink. Safe for concurrent claimers; in the
    distributed setup every worker talks to the same instance over HTTP."""

    # ── producing work ──────────────────────────────────────────────────────
    @abstractmethod
    def seed(self, targets: list[Target]) -> int:
        """Insert targets that aren't already queued. Returns how many were new."""

    # ── consuming work ──────────────────────────────────────────────────────
    @abstractmethod
    def claim(self, worker_id: str) -> Job | None:
        """Atomically take the next pending job (highest weight first)."""

    @abstractmethod
    def heartbeat(self, job_id: int, worker_id: str) -> None: ...

    @abstractmethod
    def complete(self, job_id: int, worker_id: str, report: dict) -> None: ...

    @abstractmethod
    def fail(self, job_id: int, worker_id: str, error: str, max_attempts: int) -> None: ...

    @abstractmethod
    def skip(self, job_id: int, worker_id: str, reason: str) -> None: ...

    # ── housekeeping / introspection ────────────────────────────────────────
    @abstractmethod
    def reset_stale(self, stale_minutes: int) -> int:
        """Requeue running jobs whose heartbeat is older than `stale_minutes`."""

    @abstractmethod
    def reset(self, *, failed: bool = False, skipped: bool = False, done: bool = False) -> int:
        """Requeue failed and/or skipped jobs."""

    @abstractmethod
    def stats(self) -> dict: ...

    @abstractmethod
    def iter_reports(self) -> Iterator[dict]:
        """Yield every stored per-target report (for building the corpus view)."""

    def close(self) -> None: ...
