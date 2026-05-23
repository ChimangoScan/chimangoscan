from __future__ import annotations
from ..config import Config, ConfigError
from .base import Job, Queue
from .http_queue import HttpQueue
from .sqlite_queue import SqliteQueue


def get_queue(cfg: Config) -> Queue:
    """The queue a worker / CLI talks to: a local SQLite file, or the HTTP
    coordinator. The coordinator process itself always uses SqliteQueue."""
    b = cfg.queue.backend
    if b == "sqlite":
        return SqliteQueue(cfg.queue_db)
    if b == "http":
        return HttpQueue(cfg.queue.url, cfg.queue.token)
    raise ConfigError(f"unknown queue backend '{b}' (use 'sqlite' or 'http')")


__all__ = ["Job", "Queue", "SqliteQueue", "HttpQueue", "get_queue"]
