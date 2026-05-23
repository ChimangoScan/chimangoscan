from __future__ import annotations
import json, logging, time, urllib.error, urllib.request
from collections.abc import Iterator

from ..models import Target
from .base import Job, Queue

log = logging.getLogger("scanners.httpq")

_MAX_BACKOFF = 30.0
_LIVENESS_LOG_EVERY = 30.0


class HttpQueue(Queue):
    """Client side of the coordinator. Retries transient transport errors so a
    blip in the link doesn't kill a worker mid-run. 5xx/network errors retry
    indefinitely with exponential backoff (capped); 4xx is fatal."""

    def __init__(self, url: str, token: str = "", *, retries: int = 5, backoff: float = 2.0,
                 sleeper=time.sleep, clock=time.monotonic):
        self.base = url.rstrip("/")
        self.token = token
        self.retries = retries          # kept for compat; unused for transient errors
        self.backoff = backoff
        self._sleep = sleeper
        self._clock = clock

    def _req(self, method: str, path: str, body: dict | None = None, *, want_lines: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        attempt = 0
        started = self._clock()
        last_liveness = started
        while True:
            req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    if resp.status == 204:
                        return None
                    raw = resp.read()
                    if want_lines:
                        return [json.loads(ln) for ln in raw.splitlines() if ln.strip()]
                    return json.loads(raw or b"{}")
            except urllib.error.HTTPError as e:
                if 400 <= e.code < 500:
                    raise RuntimeError(f"{method} {path}: {e.code} {e.read().decode(errors='replace')}") from e
                last = e
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last = e
            delay = min(self.backoff * (2 ** attempt), _MAX_BACKOFF)
            attempt += 1
            now = self._clock()
            if now - last_liveness >= _LIVENESS_LOG_EVERY:
                log.info("coordinator unreachable for %ds, still retrying (%s %s: %s)",
                         int(now - started), method, path, last)
                last_liveness = now
            self._sleep(delay)

    def seed(self, targets: list[Target]) -> int:
        return self._req("POST", "/seed", {"targets": [t.to_json() for t in targets]})["added"]

    def claim(self, worker_id: str) -> Job | None:
        r = self._req("POST", "/claim", {"worker_id": worker_id})
        if not r:
            return None
        j = r["job"]
        return Job(id=j["id"], target=Target.from_json(j["target"]), attempts=j["attempts"])

    def heartbeat(self, job_id: int, worker_id: str) -> None:
        self._req("POST", "/heartbeat", {"job_id": job_id, "worker_id": worker_id})

    def complete(self, job_id: int, worker_id: str, report: dict) -> None:
        self._req("POST", "/complete", {"job_id": job_id, "worker_id": worker_id, "report": report})

    def fail(self, job_id: int, worker_id: str, error: str, max_attempts: int) -> None:
        self._req("POST", "/fail", {"job_id": job_id, "worker_id": worker_id,
                                    "error": error, "max_attempts": max_attempts})

    def skip(self, job_id: int, worker_id: str, reason: str) -> None:
        self._req("POST", "/skip", {"job_id": job_id, "worker_id": worker_id, "reason": reason})

    def reset_stale(self, stale_minutes: int) -> int:
        return self._req("POST", "/reset_stale", {"stale_minutes": stale_minutes})["requeued"]

    def reset(self, *, failed: bool = False, skipped: bool = False, done: bool = False) -> int:
        return self._req("POST", "/reset", {"failed": failed, "skipped": skipped, "done": done})["requeued"]

    def stats(self) -> dict:
        return self._req("GET", "/stats")

    def iter_reports(self) -> Iterator[dict]:
        yield from self._req("GET", "/reports", want_lines=True)
