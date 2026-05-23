from __future__ import annotations
import json, sqlite3, threading, time
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path

from ..models import Target
from .base import Job, Queue

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
  id          INTEGER PRIMARY KEY,
  image       TEXT NOT NULL UNIQUE,
  name        TEXT NOT NULL,
  target_json TEXT NOT NULL,
  weight      REAL NOT NULL DEFAULT 0,
  status      TEXT NOT NULL DEFAULT 'pending',
  worker_id   TEXT,
  attempts    INTEGER NOT NULL DEFAULT 0,
  error       TEXT,
  created_at  REAL NOT NULL,
  started_at  REAL,
  heartbeat_at REAL,
  finished_at REAL
);
CREATE INDEX IF NOT EXISTS jobs_pick ON jobs(status, weight DESC, id);
CREATE TABLE IF NOT EXISTS reports (
  image       TEXT PRIMARY KEY,
  report_json TEXT NOT NULL,
  n_findings  INTEGER NOT NULL DEFAULT 0,
  finished_at REAL NOT NULL
);
"""


class SqliteQueue(Queue):
    """File-backed queue (WAL mode). Concurrency-safe for many processes on one
    host; in the distributed setup it sits behind the HTTP coordinator."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()  # serializes claim() within this process
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self):
        # closing() guarantees .close() on __exit__ — sqlite3.Connection.__exit__
        # only does commit/rollback and leaks the fd. In autocommit (isolation_level=None)
        # there is no implicit transaction to lose.
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA synchronous=NORMAL")
        return closing(c)

    def seed(self, targets: list[Target]) -> int:
        now = time.time()
        with self._conn() as c:
            before = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            c.executemany(
                "INSERT OR IGNORE INTO jobs(image,name,target_json,weight,created_at) "
                "VALUES(?,?,?,?,?)",
                [(t.image, t.name, json.dumps(t.to_json()), t.weight, now) for t in targets])
            after = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        return after - before

    def claim(self, worker_id: str) -> Job | None:
        now = time.time()
        with self._lock, self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT id,target_json,attempts FROM jobs WHERE status='pending' "
                "ORDER BY weight DESC, id LIMIT 1").fetchone()
            if not row:
                c.execute("COMMIT")
                return None
            c.execute(
                "UPDATE jobs SET status='running', worker_id=?, attempts=attempts+1, "
                "started_at=COALESCE(started_at,?), heartbeat_at=? WHERE id=?",
                (worker_id, now, now, row["id"]))
            c.execute("COMMIT")
            return Job(id=row["id"], target=Target.from_json(json.loads(row["target_json"])),
                       attempts=row["attempts"] + 1)

    def heartbeat(self, job_id: int, worker_id: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE jobs SET heartbeat_at=? WHERE id=? AND worker_id=? AND status='running'",
                      (time.time(), job_id, worker_id))

    def complete(self, job_id: int, worker_id: str, report: dict) -> None:
        now = time.time()
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute("SELECT image FROM jobs WHERE id=?", (job_id,)).fetchone()
            c.execute("UPDATE jobs SET status='done', finished_at=?, error=NULL WHERE id=?", (now, job_id))
            if r:
                c.execute("INSERT OR REPLACE INTO reports(image,report_json,n_findings,finished_at) "
                          "VALUES(?,?,?,?)",
                          (r["image"], json.dumps(report), len(report.get("findings") or []), now))
            c.execute("COMMIT")

    def fail(self, job_id: int, worker_id: str, error: str, max_attempts: int) -> None:
        with self._conn() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not row:
                c.execute("COMMIT"); return
            if row["attempts"] >= max_attempts:
                c.execute("UPDATE jobs SET status='failed', error=?, finished_at=? WHERE id=?",
                          (error[:2000], time.time(), job_id))
            else:
                c.execute("UPDATE jobs SET status='pending', worker_id=NULL, error=? WHERE id=?",
                          (error[:2000], job_id))
            c.execute("COMMIT")

    def skip(self, job_id: int, worker_id: str, reason: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE jobs SET status='skipped', error=?, finished_at=? WHERE id=?",
                      (reason[:2000], time.time(), job_id))

    def reset_stale(self, stale_minutes: int) -> int:
        cutoff = time.time() - stale_minutes * 60
        with self._conn() as c:
            cur = c.execute(
                "UPDATE jobs SET status='pending', worker_id=NULL "
                "WHERE status='running' AND COALESCE(heartbeat_at, started_at, 0) < ?", (cutoff,))
            return cur.rowcount

    def reset(self, *, failed: bool = False, skipped: bool = False, done: bool = False) -> int:
        which = ([s for s, on in (("failed", failed), ("skipped", skipped), ("done", done)) if on])
        if not which:
            return 0
        with self._conn() as c:
            cur = c.execute(
                f"UPDATE jobs SET status='pending', worker_id=NULL, error=NULL "
                f"WHERE status IN ({','.join('?' * len(which))})", which)
            return cur.rowcount

    def stats(self) -> dict:
        with self._conn() as c:
            counts = {r["status"]: r["n"] for r in
                      c.execute("SELECT status, COUNT(*) n FROM jobs GROUP BY status")}
            total = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            rep = c.execute("SELECT COUNT(*), COALESCE(SUM(n_findings),0) FROM reports").fetchone()
        out = {s: counts.get(s, 0) for s in ("pending", "running", "done", "failed", "skipped")}
        out["total"] = total
        out["reports"] = rep[0]
        out["findings"] = rep[1]
        return out

    def iter_reports(self) -> Iterator[dict]:
        with self._conn() as c:
            for row in c.execute("SELECT report_json FROM reports"):
                yield json.loads(row["report_json"])
