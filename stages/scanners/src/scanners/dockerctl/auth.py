from __future__ import annotations
import json, logging, shutil, subprocess, threading
from pathlib import Path

log = logging.getLogger("scanners.docker")


class AccountPool:
    """A round-robin pool of Docker Hub accounts. `docker login` is global per
    host (`~/.docker/config.json`), so a lock serializes rotations; pulls don't
    need the lock — they just retry after a rotation. Authenticated pulls get
    200/6h each (free tier), so a handful of accounts covers a large run."""

    def __init__(self, path: str | Path):
        accounts = json.loads(Path(path).read_text())
        self._accounts = [a for a in accounts if a.get("username") and a.get("password")]
        if not self._accounts:
            raise ValueError(f"{path}: no usable accounts")
        self._idx = 0
        self._lock = threading.Lock()
        self._logged_in: str | None = None

    def __len__(self) -> int:
        return len(self._accounts)

    @property
    def current(self) -> str:
        return self._accounts[self._idx]["username"]

    def login_current(self) -> bool:
        with self._lock:
            return self._login(self._accounts[self._idx])

    def rotate(self) -> str | None:
        """Switch to the next account. Returns its username, or None if there's
        only one account (nothing to rotate to)."""
        with self._lock:
            if len(self._accounts) <= 1:
                return None
            self._idx = (self._idx + 1) % len(self._accounts)
            acc = self._accounts[self._idx]
            self._login(acc)
            return acc["username"]

    def _login(self, acc: dict) -> bool:
        if self._logged_in == acc["username"]:
            return True
        docker = shutil.which("docker") or "docker"
        subprocess.run([docker, "logout"], capture_output=True)
        r = subprocess.run([docker, "login", "-u", acc["username"], "--password-stdin"],
                           input=acc["password"], capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            self._logged_in = acc["username"]
            log.info("docker login as %s", acc["username"])
            return True
        log.warning("docker login failed for %s: %s", acc["username"], r.stderr.strip())
        self._logged_in = None
        return False
