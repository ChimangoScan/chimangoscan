from __future__ import annotations
import logging, os, signal, socket, threading, time

from ..adapters.base import ScannerSpec
from ..config import Config
from ..dockerctl.lifecycle import TargetUnscannable
from ..jobqueue import Queue
from .worker import ScanWorker

log = logging.getLogger("scanners.runner")


def _worker_id(cfg: Config, slot: int) -> str:
    return cfg.workers.worker_id or f"{socket.gethostname()}/{os.getpid()}#{slot}"


class _Heartbeat(threading.Thread):
    def __init__(self, queue: Queue, job_id: int, wid: str, interval: int):
        super().__init__(daemon=True)
        self.queue, self.job_id, self.wid, self.interval = queue, job_id, wid, interval
        self._stop = threading.Event()

    def run(self):
        while not self._stop.wait(self.interval):
            try:
                self.queue.heartbeat(self.job_id, self.wid)
            except Exception:
                log.debug("heartbeat failed for job %s", self.job_id)

    def stop(self):
        self._stop.set()


def run(cfg: Config, queue: Queue, specs: list[ScannerSpec], *, n_workers: int, watch: bool) -> None:
    """Spawn `n_workers` threads on this machine, each draining the shared queue.
    Idempotent and crash-safe: stale jobs are reclaimed first."""
    reclaimed = queue.reset_stale(cfg.workers.stale_minutes)
    if reclaimed:
        log.info("reclaimed %d stale job(s)", reclaimed)

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    def loop(slot: int):
        wid = _worker_id(cfg, slot)
        sw = ScanWorker(cfg, specs)
        idle = 0
        while not stop.is_set():
            try:
                job = queue.claim(wid)
            except Exception as e:
                log.warning("claim failed (%s); backing off", e)
                stop.wait(10)
                continue
            if job is None:
                if not watch:
                    return
                idle = min(idle + 1, 6)
                stop.wait(min(5 * idle, 30))
                continue
            idle = 0
            hb = _Heartbeat(queue, job.id, wid, max(5, cfg.workers.heartbeat_seconds))
            hb.start()
            log.info("[%s] %s (attempt %d)", wid, job.target.image, job.attempts)
            try:
                report = sw.run(job.target)
                queue.complete(job.id, wid, report.to_json())
                log.info("[%s] %s done: %d findings, %d invocations%s", wid, job.target.image,
                         len(report.findings), len(report.invocations),
                         f" ({report.skipped_reason})" if report.skipped_reason else "")
            except TargetUnscannable as e:
                queue.skip(job.id, wid, str(e))
                log.info("[%s] %s skipped: %s", wid, job.target.image, e)
            except Exception as e:
                log.exception("[%s] %s failed", wid, job.target.image)
                queue.fail(job.id, wid, repr(e), cfg.workers.job_attempts)
            finally:
                hb.stop()

    threads = [threading.Thread(target=loop, args=(i,), name=f"w{i}", daemon=True)
               for i in range(max(1, n_workers))]
    for t in threads:
        t.start()
    try:
        while any(t.is_alive() for t in threads) and not stop.is_set():
            time.sleep(0.5)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)
